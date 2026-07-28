<?php

namespace QUI\OAuth;

use OAuth2;
use Psr\Http\Message\ServerRequestInterface;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\REST\Response;

final class AuthorizationEndpoint
{
    private const SESSION_KEY = 'quiqqer/oauth-server/authorization-consents';
    private const CONSENT_LIFETIME = 600;

    public function handle(ServerRequestInterface $Request): Response
    {
        $OAuthRequest = RequestFactory::fromPsr($Request);
        $OAuthResponse = new OAuth2\Response();
        $OAuthServer = Server::getInstance()->getOAuth2Server();

        if (!$OAuthServer->validateAuthorizeRequest($OAuthRequest, $OAuthResponse)) {
            return RestProvider::fromOAuthResponse($OAuthResponse);
        }

        $User = Handler::getSessionUser();

        if (!QUI::getUsers()->isAuth($User)) {
            return $this->renderLoginRequired($Request);
        }

        if (strtoupper($Request->getMethod()) === 'POST') {
            if (!$this->consumeConsentToken($OAuthRequest, (string)$User->getUUID())) {
                $OAuthResponse->setError(
                    400,
                    'invalid_request',
                    'The consent request is missing, expired, or has already been used.'
                );

                return RestProvider::fromOAuthResponse($OAuthResponse);
            }

            $decision = $OAuthRequest->request('decision');
            $OAuthServer->handleAuthorizeRequest(
                $OAuthRequest,
                $OAuthResponse,
                $decision === 'approve',
                (string)$User->getUUID()
            );

            return RestProvider::fromOAuthResponse($OAuthResponse);
        }

        return $this->renderConsent(
            $Request,
            $OAuthRequest,
            $this->createConsentToken($OAuthRequest, (string)$User->getUUID())
        );
    }

    private function renderLoginRequired(ServerRequestInterface $Request): Response
    {
        $Locale = QUI::getLocale();
        $project = $this->getProjectIdentity($Request);
        $returnUri = (string)$Request->getUri();
        $loginUri = $this->getLoginUri($Request, $returnUri);
        $title = $Locale->get('quiqqer/oauth-server', 'oauth.authorize.login.title');
        $body = $this->renderDocumentStart($title . ' – ' . $project['name'])
            . '<body class="quiqqer-oauth-authorization">'
            . '<main class="quiqqer-oauth-authorization-main">'
            . '<article class="quiqqer-oauth-authorization-card" aria-labelledby="oauth-login-title">'
            . $this->renderProjectIdentity($project)
            . '<section class="quiqqer-oauth-authorization-content">'
            . '<h1 id="oauth-login-title">'
            . self::escape($title)
            . '</h1><p class="quiqqer-oauth-authorization-description">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.login.description'))
            . '</p><div class="quiqqer-oauth-authorization-actions">'
            . '<a class="quiqqer-oauth-authorization-button quiqqer-oauth-authorization-button--primary" href="'
            . self::escape($loginUri) . '">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.login.action'))
            . '</a></div></section></article></main></body></html>';

        return $this->htmlResponse(401, $body);
    }

    private function renderConsent(
        ServerRequestInterface $Request,
        OAuth2\Request $OAuthRequest,
        string $consentToken
    ): Response {
        $clientId = (string)$OAuthRequest->query('client_id', $OAuthRequest->request('client_id'));
        $client = StorageFactory::create()->getClientDetails($clientId);
        $clientName = is_array($client) && !empty($client['name'])
            ? (string)$client['name']
            : $clientId;
        $scope = (string)$OAuthRequest->query('scope', $OAuthRequest->request('scope'));
        $scopes = array_values(array_filter(explode(' ', $scope)));
        $Locale = QUI::getLocale();
        $project = $this->getProjectIdentity($Request);
        $scopeItems = '';

        foreach ($scopes as $item) {
            $scopeItems .= '<li><code>' . self::escape($item) . '</code></li>';
        }

        $hiddenFields = '';

        foreach (
            [
                'response_type',
                'client_id',
                'redirect_uri',
                'scope',
                'state',
                'code_challenge',
                'code_challenge_method',
                'resource'
            ] as $name
        ) {
            $value = $OAuthRequest->query($name, $OAuthRequest->request($name));

            if (!is_string($value) || $value === '') {
                continue;
            }

            $hiddenFields .= '<input type="hidden" name="' . self::escape($name)
                . '" value="' . self::escape($value) . '">';
        }

        $title = $Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.title');
        $body = $this->renderDocumentStart($title . ' – ' . $project['name'])
            . '<body class="quiqqer-oauth-authorization">'
            . '<main class="quiqqer-oauth-authorization-main">'
            . '<article class="quiqqer-oauth-authorization-card" aria-labelledby="oauth-consent-title">'
            . $this->renderProjectIdentity($project)
            . '<section class="quiqqer-oauth-authorization-content">'
            . '<h1 id="oauth-consent-title">'
            . self::escape($title)
            . '</h1><p class="quiqqer-oauth-authorization-description">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.description', [
                'client' => $clientName
            ]))
            . '</p><section class="quiqqer-oauth-authorization-permissions" '
            . 'aria-labelledby="oauth-consent-scopes"><h2 id="oauth-consent-scopes">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.scopes'))
            . '</h2><ul>' . $scopeItems . '</ul></section>'
            . '<form class="quiqqer-oauth-authorization-actions" method="post" action="'
            . self::escape($Request->getUri()->getPath()) . '">'
            . $hiddenFields
            . '<input type="hidden" name="_oauth_consent_token" value="' . self::escape($consentToken) . '">'
            . '<button class="quiqqer-oauth-authorization-button quiqqer-oauth-authorization-button--secondary" '
            . 'type="submit" name="decision" value="deny">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.deny'))
            . '</button>'
            . '<button class="quiqqer-oauth-authorization-button quiqqer-oauth-authorization-button--primary" '
            . 'type="submit" name="decision" value="approve">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.approve'))
            . '</button></form></section></article></main></body></html>';

        return $this->htmlResponse(200, $body);
    }

    private function htmlResponse(int $status, string $body): Response
    {
        $Response = new Response($status);
        $Response->getBody()->write($body);

        return $Response
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withHeader(
                'Content-Security-Policy',
                "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "
                . "img-src 'self' data:; style-src 'self'"
            );
    }

    private function renderDocumentStart(string $title): string
    {
        return '<!doctype html><html lang="' . self::escape(QUI::getLocale()->getCurrent()) . '">'
            . '<head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . self::escape($title) . '</title>'
            . '<link rel="stylesheet" href="'
            . self::escape(URL_OPT_DIR . 'quiqqer/core/bin/css/variables.css')
            . '"><link rel="stylesheet" href="'
            . self::escape(URL_OPT_DIR . 'quiqqer/oauth-server/bin/css/authorization.css')
            . '"></head>';
    }

    /**
     * The rewrite resolves the project from the current request domain.
     *
     * @return array{name: string, logo: string|null}
     */
    private function getProjectIdentity(ServerRequestInterface $Request): array
    {
        $projectName = $Request->getUri()->getHost();
        $logo = null;

        if ($projectName === '') {
            $projectName = 'QUIQQER';
        }

        try {
            $Project = QUI::getRewrite()->getProject();

            if (!$Project) {
                return [
                    'name' => $projectName,
                    'logo' => null
                ];
            }

            $projectName = trim($Project->getTitle());

            if ($projectName === '') {
                $projectName = trim($Project->getName());
            }

            if ($projectName === '') {
                $projectName = $Request->getUri()->getHost() ?: 'QUIQQER';
            }

            if ($Project->getConfig('logo')) {
                $Logo = $Project->getMedia()->getLogoImage();
                $logo = $Logo?->getSizeCacheUrl(320, 120);
            }
        } catch (QUI\Exception) {
        }

        return [
            'name' => $projectName,
            'logo' => $logo
        ];
    }

    /**
     * @param array{name: string, logo: string|null} $project
     */
    private function renderProjectIdentity(array $project): string
    {
        if ($project['logo'] !== null) {
            return '<header class="quiqqer-oauth-authorization-brand">'
                . '<img class="quiqqer-oauth-authorization-logo" src="'
                . self::escape($project['logo'])
                . '" alt="' . self::escape($project['name']) . '">'
                . '</header>';
        }

        return '<header class="quiqqer-oauth-authorization-brand">'
            . '<p class="quiqqer-oauth-authorization-brandName">'
            . self::escape($project['name'])
            . '</p>'
            . '</header>';
    }

    private function createConsentToken(OAuth2\Request $Request, string $userUuid): string
    {
        $token = bin2hex(random_bytes(32));
        $consents = QUI::getSession()->get(self::SESSION_KEY);
        $consents = is_array($consents) ? $consents : [];
        $now = time();

        foreach ($consents as $key => $consent) {
            if (!is_array($consent) || (int)($consent['expires'] ?? 0) < $now) {
                unset($consents[$key]);
            }
        }

        $consents[$token] = [
            'fingerprint' => $this->fingerprint($Request),
            'user_uuid' => $userUuid,
            'expires' => $now + self::CONSENT_LIFETIME
        ];
        QUI::getSession()->set(self::SESSION_KEY, array_slice($consents, -10, null, true));

        return $token;
    }

    private function consumeConsentToken(OAuth2\Request $Request, string $userUuid): bool
    {
        $token = $Request->request('_oauth_consent_token');

        if (!is_string($token) || $token === '') {
            return false;
        }

        $consents = QUI::getSession()->get(self::SESSION_KEY);

        if (!is_array($consents) || !isset($consents[$token]) || !is_array($consents[$token])) {
            return false;
        }

        $consent = $consents[$token];
        unset($consents[$token]);
        QUI::getSession()->set(self::SESSION_KEY, $consents);

        return (int)($consent['expires'] ?? 0) >= time()
            && hash_equals((string)($consent['user_uuid'] ?? ''), $userUuid)
            && hash_equals((string)($consent['fingerprint'] ?? ''), $this->fingerprint($Request));
    }

    private function fingerprint(OAuth2\Request $Request): string
    {
        $parameters = [];

        foreach (
            [
                'response_type',
                'client_id',
                'redirect_uri',
                'scope',
                'state',
                'code_challenge',
                'code_challenge_method',
                'resource'
            ] as $name
        ) {
            $parameters[$name] = (string)$Request->query($name, $Request->request($name));
        }

        return hash('sha256', json_encode($parameters, JSON_THROW_ON_ERROR));
    }

    private function getLoginUri(ServerRequestInterface $Request, string $returnUri): string
    {
        try {
            $configured = QUI::getPackage('quiqqer/oauth-server')
                ->getConfig()
                ?->getValue('general', 'authorization_login_url');
        } catch (QUI\Exception) {
            $configured = null;
        }

        if (!is_string($configured) || trim($configured) === '') {
            $uri = $Request->getUri();
            $configured = $uri->getScheme() . '://' . $uri->getAuthority() . '/';
        }

        $separator = str_contains($configured, '?') ? '&' : '?';

        return $configured . $separator . http_build_query([
            'quiqqer_oauth_return' => $returnUri
        ]);
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

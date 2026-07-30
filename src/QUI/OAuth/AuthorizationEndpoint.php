<?php

namespace QUI\OAuth;

use OAuth2;
use Psr\Http\Message\ServerRequestInterface;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Consent\Context;
use QUI\OAuth\Consent\Presentation;
use QUI\REST\Response;

final class AuthorizationEndpoint
{
    private const SESSION_KEY = 'quiqqer/oauth-server/authorization-consents';
    private const CONSENT_LIFETIME = 600;

    public function handle(ServerRequestInterface $Request): Response
    {
        $Locale = QUI::getLocale();
        $previousLanguage = $Locale->getCurrent();
        $projectLanguage = $this->getProjectLanguage();
        $restoreLanguage = $projectLanguage !== null
            && $projectLanguage !== $previousLanguage;

        if ($restoreLanguage) {
            $Locale->setCurrent($projectLanguage);
        }

        try {
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
                    return $this->renderExpiredConsent($Request, $OAuthRequest);
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
        } finally {
            if ($restoreLanguage) {
                $Locale->setCurrent($previousLanguage);
            }
        }
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
            . '</p><div class="quiqqer-oauth-authorization-login" '
            . 'id="quiqqer-oauth-login-control" aria-live="polite"></div>'
            . '<noscript><div class="quiqqer-oauth-authorization-actions">'
            . '<a class="quiqqer-oauth-authorization-button '
            . 'quiqqer-oauth-authorization-button--primary" href="'
            . self::escape($loginUri) . '">'
            . self::escape($Locale->get('quiqqer/oauth-server', 'oauth.authorize.login.action'))
            . '</a></div></noscript></section></article></main>'
            . $this->renderLoginScripts($returnUri)
            . '</body></html>';

        return $this->htmlResponse(200, $body, true);
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
        $title = $Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.title');
        $Presentation = new Presentation(
            $title,
            $Locale->get('quiqqer/oauth-server', 'oauth.authorize.consent.description', [
                'client' => $clientName
            ])
        );

        $Presentation->addSection(
            $Locale->get(
                'quiqqer/oauth-server',
                'oauth.authorize.consent.scopes'
            ),
            $scopes
        );

        $Context = new Context(
            Handler::getSessionUser(),
            $clientId,
            $clientName,
            (string)$OAuthRequest->query(
                'resource',
                $OAuthRequest->request('resource')
            ),
            $scopes
        );

        try {
            QUI::getEvents()->fireEvent(
                'quiqqerOAuthConsentPresentation',
                [$Context, $Presentation]
            );
        } catch (\Throwable $Exception) {
            QUI\System\Log::writeException($Exception);
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

        $body = $this->renderDocumentStart(
            $Presentation->getTitle() . ' – ' . $project['name']
        )
            . '<body class="quiqqer-oauth-authorization">'
            . '<main class="quiqqer-oauth-authorization-main">'
            . '<article class="quiqqer-oauth-authorization-card" aria-labelledby="oauth-consent-title">'
            . $this->renderProjectIdentity($project)
            . '<section class="quiqqer-oauth-authorization-content">'
            . '<h1 id="oauth-consent-title">'
            . self::escape($Presentation->getTitle())
            . '</h1><p class="quiqqer-oauth-authorization-description">'
            . self::escape($Presentation->getDescription())
            . '</p>' . $this->renderConsentSections($Presentation)
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

        return $this->htmlResponse(
            200,
            $body,
            false,
            (string)$OAuthRequest->query(
                'redirect_uri',
                $OAuthRequest->request('redirect_uri')
            )
        );
    }

    private function renderConsentSections(
        Presentation $Presentation
    ): string {
        $result = '';

        foreach ($Presentation->getSections() as $index => $section) {
            $headingId = 'oauth-consent-section-' . $index;
            $items = '';

            foreach ($section['items'] as $item) {
                $type = '';

                if ($item['type'] !== '') {
                    $type = '<span class="quiqqer-oauth-authorization-permissionType">'
                        . self::escape($item['type'])
                        . '</span> ';
                }

                $items .= '<li><span class="quiqqer-oauth-authorization-permission">'
                    . $type
                    . '<code>' . self::escape($item['name']) . '</code>'
                    . '</span></li>';
            }

            $result .= '<section class="quiqqer-oauth-authorization-permissions" '
                . 'aria-labelledby="' . $headingId . '">'
                . '<h2 id="' . $headingId . '">'
                . self::escape($section['title'])
                . '</h2><ul>' . $items . '</ul></section>';
        }

        return $result;
    }

    private function renderExpiredConsent(
        ServerRequestInterface $Request,
        OAuth2\Request $OAuthRequest
    ): Response {
        $Locale = QUI::getLocale();
        $project = $this->getProjectIdentity($Request);
        $title = $Locale->get(
            'quiqqer/oauth-server',
            'oauth.authorize.expired.title'
        );
        $retryUri = $this->getAuthorizationRetryUri($Request, $OAuthRequest);
        $body = $this->renderDocumentStart($title . ' – ' . $project['name'])
            . '<body class="quiqqer-oauth-authorization">'
            . '<main class="quiqqer-oauth-authorization-main">'
            . '<article class="quiqqer-oauth-authorization-card" aria-labelledby="oauth-expired-title">'
            . $this->renderProjectIdentity($project)
            . '<section class="quiqqer-oauth-authorization-content">'
            . '<h1 id="oauth-expired-title">' . self::escape($title) . '</h1>'
            . '<p class="quiqqer-oauth-authorization-description">'
            . self::escape($Locale->get(
                'quiqqer/oauth-server',
                'oauth.authorize.expired.description'
            ))
            . '</p><div class="quiqqer-oauth-authorization-actions">'
            . '<a class="quiqqer-oauth-authorization-button '
            . 'quiqqer-oauth-authorization-button--primary" href="'
            . self::escape($retryUri) . '">'
            . self::escape($Locale->get(
                'quiqqer/oauth-server',
                'oauth.authorize.expired.action'
            ))
            . '</a></div></section></article></main></body></html>';

        return $this->htmlResponse(400, $body);
    }

    private function htmlResponse(
        int $status,
        string $body,
        bool $loginControl = false,
        ?string $redirectUri = null
    ): Response {
        $Response = new Response($status);
        $Response->getBody()->write($body);
        $formAction = ["'self'"];
        $redirectOrigin = self::getHttpOrigin($redirectUri);

        if ($redirectOrigin !== null) {
            $formAction[] = $redirectOrigin;
        }

        $contentSecurityPolicy = "default-src 'none'; base-uri 'none'; "
            . 'form-action ' . implode(' ', $formAction)
            . "; frame-ancestors 'none'; img-src 'self' data:; "
            . "style-src 'self'";

        if ($loginControl) {
            $contentSecurityPolicy .= " 'unsafe-inline'; script-src 'self'; "
                . "connect-src 'self'; font-src 'self' data:";
        }

        return $Response
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withHeader(
                'Content-Security-Policy',
                $contentSecurityPolicy
            );
    }

    private function getAuthorizationRetryUri(
        ServerRequestInterface $Request,
        OAuth2\Request $OAuthRequest
    ): string {
        $query = [];

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

            if (is_string($value) && $value !== '') {
                $query[$name] = $value;
            }
        }

        return $Request->getUri()->getPath() . '?' . http_build_query($query);
    }

    private static function getHttpOrigin(?string $uri): ?string
    {
        if ($uri === null || $uri === '') {
            return null;
        }

        $parts = parse_url($uri);

        if (!is_array($parts)) {
            return null;
        }

        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = (string)($parts['host'] ?? '');

        if (
            !in_array($scheme, ['http', 'https'], true)
            || $host === ''
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            return null;
        }

        if (str_contains($host, ':') && $host[0] !== '[') {
            $host = '[' . $host . ']';
        }

        $origin = $scheme . '://' . $host;

        if (isset($parts['port'])) {
            $origin .= ':' . $parts['port'];
        }

        return $origin;
    }

    private function renderLoginScripts(string $returnUri): string
    {
        $scriptAttributes = [
            'data-return-uri' => $returnUri,
            'data-language' => QUI::getLocale()->getCurrent(),
            'data-url-dir' => URL_DIR,
            'data-url-bin-dir' => URL_BIN_DIR,
            'data-url-opt-dir' => URL_OPT_DIR,
            'data-url-sys-dir' => URL_SYS_DIR,
            'data-url-var-dir' => URL_VAR_DIR
        ];
        $attributes = '';

        foreach ($scriptAttributes as $name => $value) {
            $attributes .= ' ' . $name . '="' . self::escape($value) . '"';
        }

        return '<script src="'
            . self::escape(
                URL_OPT_DIR
                . 'bin/quiqqer-asset/requirejs/requirejs/require.js'
            )
            . '"></script><script src="'
            . self::escape(URL_OPT_DIR . 'bin/qui/qui/lib/mootools-core.js')
            . '"></script><script src="'
            . self::escape(URL_OPT_DIR . 'bin/qui/qui/lib/mootools-more.js')
            . '"></script><script src="'
            . self::escape(URL_OPT_DIR . 'bin/qui/qui/lib/moofx.js')
            . '"></script><script src="'
            . self::escape(
                URL_OPT_DIR
                . 'quiqqer/oauth-server/bin/js/authorization-login.js'
            )
            . '"' . $attributes . '></script>';
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

    private function getProjectLanguage(): ?string
    {
        try {
            $Project = QUI::getRewrite()->getProject();

            if (!$Project) {
                return null;
            }

            $language = trim($Project->getLang());

            return $language !== '' ? $language : null;
        } catch (QUI\Exception) {
            return null;
        }
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

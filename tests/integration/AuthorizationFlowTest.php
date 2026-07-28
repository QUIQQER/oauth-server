<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use OAuth2;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Metadata;
use QUI\OAuth\Middleware\ResourceController;
use QUI\OAuth\RestProvider;
use QUI\OAuth\Server;
use QUI\OAuth\Setup;
use QUI\REST\Server as RestServer;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

class AuthorizationFlowTest extends OAuthDatabaseTestCase
{
    private const REDIRECT_URI = 'https://chat.openai.com/aip/oauth/callback';
    private const TEST_BASE_HOST = 'https://oauth.example.test';

    protected function setUp(): void
    {
        parent::setUp();

        $RestServer = new RestServer([
            'basePath' => '/api',
            'baseHost' => self::TEST_BASE_HOST
        ]);
        (new RestProvider())->register($RestServer);

        $ServerProperty = new \ReflectionProperty(RestServer::class, 'currentInstance');
        $ServerProperty->setValue(null, $RestServer);
    }

    public function testAuthorizationCodePkceRefreshResourceAndRevocationFlow(): void
    {
        $resource = Metadata::resource(RestServer::getCurrentInstance());
        $clientId = $this->createAuthorizationClient($resource);
        $client = Handler::getOAuthClient($clientId);
        $verifier = str_repeat('a', 64);
        $challenge = self::challenge($verifier);
        $state = bin2hex(random_bytes(16));
        $OAuthServer = Server::getInstance()->getOAuth2Server();
        $authorizationRequest = $this->authorizationRequest(
            $clientId,
            $challenge,
            $state,
            $resource
        );
        $authorizationResponse = new OAuth2\Response();

        self::getConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_clients')),
            ['user_id' => 99999999],
            ['client_id' => $clientId]
        );

        $OAuthServer->handleAuthorizeRequest(
            $authorizationRequest,
            $authorizationResponse,
            true,
            (string)QUI::getUsers()->getSystemUser()->getUUID()
        );

        self::assertSame(302, $authorizationResponse->getStatusCode());
        $location = $authorizationResponse->getHttpHeader('Location');
        self::assertIsString($location);
        parse_str((string)parse_url($location, PHP_URL_QUERY), $redirectQuery);
        self::assertSame($state, $redirectQuery['state'] ?? null);
        self::assertNotEmpty($redirectQuery['code']);
        $code = (string)$redirectQuery['code'];

        $codeData = self::getConnection()->createQueryBuilder()
            ->select('*')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_authorization_codes')))
            ->where('authorization_code = :code')
            ->setParameter('code', $code)
            ->executeQuery()
            ->fetchAssociative();
        self::assertIsArray($codeData);
        self::assertSame($resource, $codeData['resource']);
        self::assertSame((string)QUI::getUsers()->getSystemUser()->getUUID(), $codeData['user_id']);

        $TokenEndpoint = new QUI\OAuth\TokenEndpoint();
        $tokenResponse = $TokenEndpoint->handle($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => $verifier
            ]
        ));
        $tokens = json_decode((string)$tokenResponse->getBody(), true);

        self::assertSame(200, $tokenResponse->getStatusCode());
        self::assertIsArray($tokens);
        self::assertNotEmpty($tokens['access_token']);
        self::assertNotEmpty($tokens['refresh_token']);
        $Storage = QUI\OAuth\StorageFactory::create();
        $accessData = $Storage->getAccessToken((string)$tokens['access_token']);
        $refreshData = $Storage->getRefreshToken((string)$tokens['refresh_token']);
        self::assertIsArray($accessData);
        self::assertIsArray($refreshData);
        self::assertSame($resource, $accessData['resource']);
        self::assertSame($resource, $refreshData['resource']);
        self::assertSame((string)QUI::getUsers()->getSystemUser()->getUUID(), $accessData['user_id']);

        Handler::setSessionUser(QUI::getUsers()->getNobody());
        $Controller = $OAuthServer->getResourceController();
        self::assertInstanceOf(ResourceController::class, $Controller);
        $Controller->verify(
            '/quiqqer_oauth_test',
            new ServerRequest('GET', '/quiqqer_oauth_test', [
                'Authorization' => 'Bearer ' . $tokens['access_token']
            ])
        );
        self::assertSame(
            (string)QUI::getUsers()->getSystemUser()->getUUID(),
            (string)Handler::getSessionUser()->getUUID()
        );

        $refreshResponse = $TokenEndpoint->handle($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $tokens['refresh_token']
            ]
        ));
        $refreshedTokens = json_decode((string)$refreshResponse->getBody(), true);
        self::assertSame(200, $refreshResponse->getStatusCode());
        self::assertIsArray($refreshedTokens);
        self::assertNotSame($tokens['refresh_token'], $refreshedTokens['refresh_token']);
        self::assertFalse($Storage->getRefreshToken((string)$tokens['refresh_token']));
        self::assertSame(
            $resource,
            $Storage->getAccessToken((string)$refreshedTokens['access_token'])['resource']
        );

        $revokeResponse = $TokenEndpoint->revoke($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'token' => $refreshedTokens['access_token'],
                'token_type_hint' => 'access_token'
            ]
        ));
        self::assertSame(200, $revokeResponse->getStatusCode());
        self::assertFalse($Storage->getAccessToken((string)$refreshedTokens['access_token']));
    }

    public function testAuthorizationRejectsMissingPkceAndUnregisteredResource(): void
    {
        $resource = Metadata::resource(RestServer::getCurrentInstance());
        $clientId = $this->createAuthorizationClient($resource);
        $OAuthServer = Server::getInstance()->getOAuth2Server();
        $missingPkceResponse = new OAuth2\Response();

        self::assertFalse($OAuthServer->validateAuthorizeRequest(
            $this->authorizationRequest($clientId, null, 'state-one', $resource),
            $missingPkceResponse
        ));
        self::assertSame(
            'invalid_request',
            self::redirectError($missingPkceResponse)
        );

        $invalidResourceResponse = new OAuth2\Response();
        self::assertFalse($OAuthServer->validateAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                self::challenge(str_repeat('b', 64)),
                'state-two',
                'https://other.example.test/api'
            ),
            $invalidResourceResponse
        ));
        self::assertSame(
            'invalid_target',
            self::redirectError($invalidResourceResponse)
        );
    }

    public function testConsentPageEscapesClientDataAndRejectsReplayedConsent(): void
    {
        $RestServer = RestServer::getCurrentInstance();
        $resource = Metadata::resource($RestServer);
        $clientId = $this->createAuthorizationClient(
            $resource,
            self::TEST_PREFIX . '<script>alert(1)</script>'
        );
        $verifier = str_repeat('c', 64);
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => '/quiqqer_oauth_test',
            'state' => 'consent-state',
            'code_challenge' => self::challenge($verifier),
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];

        Handler::setSessionUser(QUI::getUsers()->getSystemUser());
        $getResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('GET', '/api/oauth/authorize'))->withQueryParams($query)
        );
        $body = (string)$getResponse->getBody();

        self::assertSame(200, $getResponse->getStatusCode());
        self::assertStringNotContainsString('<script>alert(1)</script>', $body);
        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $body);
        self::assertStringContainsString('quiqqer-oauth-authorization-card', $body);
        self::assertStringContainsString('quiqqer/oauth-server/bin/css/authorization.css', $body);

        $Project = QUI::getRewrite()->getProject();

        if ($Project?->getConfig('logo')) {
            self::assertStringContainsString('quiqqer-oauth-authorization-logo', $body);
            self::assertStringNotContainsString('quiqqer-oauth-authorization-brandName', $body);
        } else {
            self::assertStringNotContainsString('quiqqer-oauth-authorization-logo', $body);
            self::assertStringContainsString('quiqqer-oauth-authorization-brandName', $body);
        }

        self::assertStringContainsString("style-src 'self'", $getResponse->getHeaderLine('Content-Security-Policy'));
        self::assertStringNotContainsString(
            "'unsafe-inline'",
            $getResponse->getHeaderLine('Content-Security-Policy')
        );
        self::assertMatchesRegularExpression(
            '/name="_oauth_consent_token" value="([a-f0-9]{64})"/',
            $body
        );
        preg_match('/name="_oauth_consent_token" value="([a-f0-9]{64})"/', $body, $matches);
        $post = $query + [
            '_oauth_consent_token' => $matches[1],
            'decision' => 'approve'
        ];

        $postResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('POST', '/api/oauth/authorize'))->withParsedBody($post)
        );
        self::assertSame(302, $postResponse->getStatusCode());

        $replayResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('POST', '/api/oauth/authorize'))->withParsedBody($post)
        );
        self::assertSame(400, $replayResponse->getStatusCode());
    }

    private function createAuthorizationClient(
        string $resource,
        ?string $name = null
    ): string {
        return Handler::createAuthorizationClient(
            QUI::getUsers()->getSystemUser(),
            [
                '/quiqqer_oauth_test' => [
                    'active' => true,
                    'unlimitedCalls' => true,
                    'maxCalls' => 0,
                    'maxCallsType' => 'absolute'
                ]
            ],
            $name ?? self::TEST_PREFIX . bin2hex(random_bytes(6)),
            [self::REDIRECT_URI],
            [$resource]
        );
    }

    private function authorizationRequest(
        string $clientId,
        ?string $challenge,
        string $state,
        string $resource
    ): OAuth2\Request {
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => '/quiqqer_oauth_test',
            'state' => $state,
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];

        if ($challenge !== null) {
            $query['code_challenge'] = $challenge;
        }

        return new OAuth2\Request($query);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function tokenRequest(string $clientId, string $clientSecret, array $body): ServerRequest
    {
        return (new ServerRequest(
            'POST',
            '/api/oauth/token',
            [
                'Authorization' => 'Basic ' . base64_encode($clientId . ':' . $clientSecret),
                'Content-Type' => 'application/x-www-form-urlencoded'
            ]
        ))->withParsedBody($body);
    }

    private static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private static function redirectError(OAuth2\Response $Response): ?string
    {
        $location = $Response->getHttpHeader('Location');
        parse_str((string)parse_url((string)$location, PHP_URL_QUERY), $query);

        return isset($query['error']) && is_string($query['error']) ? $query['error'] : null;
    }
}

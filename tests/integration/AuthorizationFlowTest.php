<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use OAuth2;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Consent\Context;
use QUI\OAuth\Consent\Presentation;
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
        $issuedAt = time();
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
        $configuredRefreshLifetime = QUI::getPackage(
            'quiqqer/oauth-server'
        )->getConfig()?->getValue('general', 'refresh_token_lifetime');
        $expectedRefreshLifetime = is_numeric($configuredRefreshLifetime)
            && (int)$configuredRefreshLifetime > 0
                ? (int)$configuredRefreshLifetime
                : 1209600;
        self::assertGreaterThanOrEqual(
            $issuedAt + $expectedRefreshLifetime,
            $refreshData['expires']
        );
        self::assertLessThanOrEqual(
            time() + $expectedRefreshLifetime,
            $refreshData['expires']
        );

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
        $rotatedToken = $Storage->getRefreshToken(
            (string)$tokens['refresh_token']
        );
        $replacementToken = $Storage->getRefreshToken(
            (string)$refreshedTokens['refresh_token']
        );
        self::assertIsArray($rotatedToken);
        self::assertIsArray($replacementToken);
        self::assertSame(
            $refreshedTokens['refresh_token'],
            $rotatedToken['replaced_by']
        );
        self::assertSame(
            $rotatedToken['token_family_id'],
            $replacementToken['token_family_id']
        );
        self::assertSame(
            $resource,
            $Storage->getAccessToken((string)$refreshedTokens['access_token'])['resource']
        );

        $retryResponse = (new QUI\OAuth\TokenEndpoint())->handle(
            $this->tokenRequest(
                $clientId,
                (string)$client['client_secret'],
                [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $tokens['refresh_token']
                ]
            )
        );
        $retryTokens = json_decode(
            (string)$retryResponse->getBody(),
            true
        );
        self::assertSame(200, $retryResponse->getStatusCode());
        self::assertIsArray($retryTokens);
        self::assertSame(
            $refreshedTokens['access_token'],
            $retryTokens['access_token']
        );
        self::assertSame(
            $refreshedTokens['refresh_token'],
            $retryTokens['refresh_token']
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

    public function testRefreshTokenReplayAfterGraceRevokesFamily(): void
    {
        $resource = Metadata::resource(RestServer::getCurrentInstance());
        $clientId = $this->createAuthorizationClient($resource);
        $client = Handler::getOAuthClient($clientId);
        $refreshToken = bin2hex(random_bytes(20));
        $Storage = QUI\OAuth\StorageFactory::create();
        $Storage->setRefreshToken(
            $refreshToken,
            $clientId,
            (string)QUI::getUsers()->getSystemUser()->getUUID(),
            time() + 3600,
            '/quiqqer_oauth_test'
        );
        $Storage->setRefreshTokenResource($refreshToken, $resource);
        $TokenEndpoint = new QUI\OAuth\TokenEndpoint();

        $refreshResponse = $TokenEndpoint->handle($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken
            ]
        ));
        $replacement = json_decode(
            (string)$refreshResponse->getBody(),
            true
        );
        self::assertSame(200, $refreshResponse->getStatusCode());
        self::assertIsArray($replacement);

        self::getConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(
                Setup::getTable('oauth_refresh_tokens')
            ),
            ['replaced_at' => '2000-01-01 00:00:00'],
            ['refresh_token' => $refreshToken]
        );

        $replayResponse = (new QUI\OAuth\TokenEndpoint())->handle(
            $this->tokenRequest(
                $clientId,
                (string)$client['client_secret'],
                [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $refreshToken
                ]
            )
        );
        $replayError = json_decode(
            (string)$replayResponse->getBody(),
            true
        );
        self::assertSame(400, $replayResponse->getStatusCode());
        self::assertIsArray($replayError);
        self::assertSame('invalid_grant', $replayError['error']);
        self::assertStringContainsString(
            'reuse detected',
            $replayError['error_description']
        );

        $usedToken = $Storage->getRefreshToken($refreshToken);
        $replacementToken = $Storage->getRefreshToken(
            (string)$replacement['refresh_token']
        );
        self::assertIsArray($usedToken);
        self::assertIsArray($replacementToken);
        self::assertNotEmpty($usedToken['revoked_at']);
        self::assertNotEmpty($replacementToken['revoked_at']);
        self::assertFalse($Storage->getAccessToken(
            (string)$replacement['access_token']
        ));

        $revokedFamilyResponse = $TokenEndpoint->handle(
            $this->tokenRequest(
                $clientId,
                (string)$client['client_secret'],
                [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $replacement['refresh_token']
                ]
            )
        );
        self::assertSame(400, $revokedFamilyResponse->getStatusCode());
    }

    public function testRefreshTokenRevocationRevokesCompleteFamily(): void
    {
        $resource = Metadata::resource(RestServer::getCurrentInstance());
        $clientId = $this->createAuthorizationClient($resource);
        $client = Handler::getOAuthClient($clientId);
        $refreshToken = bin2hex(random_bytes(20));
        $Storage = QUI\OAuth\StorageFactory::create();
        $Storage->setRefreshToken(
            $refreshToken,
            $clientId,
            (string)QUI::getUsers()->getSystemUser()->getUUID(),
            time() + 3600,
            '/quiqqer_oauth_test'
        );
        $Storage->setRefreshTokenResource($refreshToken, $resource);
        $TokenEndpoint = new QUI\OAuth\TokenEndpoint();

        $refreshResponse = $TokenEndpoint->handle($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken
            ]
        ));
        $replacement = json_decode(
            (string)$refreshResponse->getBody(),
            true
        );
        self::assertSame(200, $refreshResponse->getStatusCode());
        self::assertIsArray($replacement);
        self::assertIsArray($Storage->getAccessToken(
            (string)$replacement['access_token']
        ));

        $revokeResponse = $TokenEndpoint->revoke($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'token' => $replacement['refresh_token'],
                'token_type_hint' => 'refresh_token'
            ]
        ));
        self::assertSame(200, $revokeResponse->getStatusCode());

        $usedToken = $Storage->getRefreshToken($refreshToken);
        $replacementToken = $Storage->getRefreshToken(
            (string)$replacement['refresh_token']
        );
        self::assertIsArray($usedToken);
        self::assertIsArray($replacementToken);
        self::assertNotEmpty($usedToken['revoked_at']);
        self::assertNotEmpty($replacementToken['revoked_at']);
        self::assertFalse($Storage->getAccessToken(
            (string)$replacement['access_token']
        ));
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

    public function testUnauthenticatedAuthorizationRendersLoginControl(): void
    {
        $RestServer = RestServer::getCurrentInstance();
        $resource = Metadata::resource($RestServer);
        $clientId = $this->createAuthorizationClient($resource);
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => '/quiqqer_oauth_test',
            'state' => 'login-control-state',
            'code_challenge' => self::challenge(str_repeat('l', 64)),
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];

        Handler::setSessionUser(QUI::getUsers()->getNobody());
        $Response = $RestServer->getSlim()->handle(
            (new ServerRequest(
                'GET',
                self::TEST_BASE_HOST . '/api/oauth/authorize?'
                . http_build_query($query)
            ))->withQueryParams($query)
        );
        $body = (string)$Response->getBody();
        $contentSecurityPolicy = $Response->getHeaderLine(
            'Content-Security-Policy'
        );

        self::assertSame(200, $Response->getStatusCode());
        self::assertStringContainsString(
            'id="quiqqer-oauth-login-control"',
            $body
        );
        self::assertStringContainsString(
            'quiqqer/oauth-server/bin/js/authorization-login.js',
            $body
        );
        self::assertStringContainsString(
            'data-return-uri="https://oauth.example.test/api/oauth/authorize?',
            $body
        );
        self::assertStringContainsString(
            'state=login-control-state',
            $body
        );
        self::assertStringContainsString(
            "script-src 'self'",
            $contentSecurityPolicy
        );
        self::assertStringContainsString(
            "connect-src 'self'",
            $contentSecurityPolicy
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
        self::assertStringContainsString(
            "form-action 'self' https://chat.openai.com",
            $getResponse->getHeaderLine('Content-Security-Policy')
        );
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
        self::assertSame(
            'text/html; charset=utf-8',
            $replayResponse->getHeaderLine('Content-Type')
        );
        self::assertStringContainsString(
            'id="oauth-expired-title"',
            (string)$replayResponse->getBody()
        );
        self::assertStringContainsString(
            '/api/oauth/authorize?',
            (string)$replayResponse->getBody()
        );
        self::assertStringNotContainsString(
            '"error":"invalid_request"',
            (string)$replayResponse->getBody()
        );
    }

    public function testConsentDenialRedirectsBackToClient(): void
    {
        $RestServer = RestServer::getCurrentInstance();
        $resource = Metadata::resource($RestServer);
        $redirectUri = 'http://127.0.0.1:43123/callback/codex';
        $clientId = $this->createAuthorizationClient(
            $resource,
            null,
            $redirectUri
        );
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => '/quiqqer_oauth_test',
            'state' => 'denied-consent-state',
            'code_challenge' => self::challenge(str_repeat('d', 64)),
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];

        Handler::setSessionUser(QUI::getUsers()->getSystemUser());
        $getResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('GET', '/api/oauth/authorize'))->withQueryParams($query)
        );
        $body = (string)$getResponse->getBody();
        self::assertStringContainsString(
            "form-action 'self' http://127.0.0.1:43123",
            $getResponse->getHeaderLine('Content-Security-Policy')
        );
        preg_match('/name="_oauth_consent_token" value="([a-f0-9]{64})"/', $body, $matches);
        self::assertArrayHasKey(1, $matches);

        $postResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('POST', '/api/oauth/authorize'))->withParsedBody($query + [
                '_oauth_consent_token' => $matches[1],
                'decision' => 'deny'
            ])
        );

        self::assertSame(302, $postResponse->getStatusCode());
        self::assertStringStartsWith(
            $redirectUri,
            $postResponse->getHeaderLine('Location')
        );
        parse_str(
            (string)parse_url($postResponse->getHeaderLine('Location'), PHP_URL_QUERY),
            $redirectQuery
        );
        self::assertSame('access_denied', $redirectQuery['error'] ?? null);
        self::assertSame('denied-consent-state', $redirectQuery['state'] ?? null);
    }

    public function testConsentPresentationCanBeExtendedByModules(): void
    {
        $RestServer = RestServer::getCurrentInstance();
        $resource = Metadata::resource($RestServer);
        $clientId = $this->createAuthorizationClient($resource);
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => '/quiqqer_oauth_test',
            'state' => 'custom-consent-state',
            'code_challenge' => self::challenge(str_repeat('e', 64)),
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];
        $capturedContext = null;
        $listener = static function (
            Context $Context,
            Presentation $Presentation
        ) use (&$capturedContext): void {
            $capturedContext = $Context;
            $Presentation
                ->setTitle('Customized MCP consent')
                ->setDescription('User-specific MCP functions')
                ->addSection('Available MCP functions', [
                    [
                        'type' => 'Resource',
                        'name' => 'project_<information>'
                    ],
                    [
                        'type' => 'Tool',
                        'name' => 'project_update'
                    ]
                ]);
        };

        Handler::setSessionUser(QUI::getUsers()->getSystemUser());
        QUI::getEvents()->addEvent(
            'onQuiqqerOAuthConsentPresentation',
            $listener
        );

        try {
            $Response = $RestServer->getSlim()->handle(
                (new ServerRequest(
                    'GET',
                    '/api/oauth/authorize'
                ))->withQueryParams($query)
            );
        } finally {
            QUI::getEvents()->removeEvent(
                'onQuiqqerOAuthConsentPresentation',
                $listener
            );
        }

        $body = (string)$Response->getBody();
        self::assertSame(200, $Response->getStatusCode());
        self::assertInstanceOf(Context::class, $capturedContext);
        self::assertSame(
            QUI::getUsers()->getSystemUser()->getUUID(),
            $capturedContext->getUser()->getUUID()
        );
        self::assertSame($clientId, $capturedContext->getClientId());
        self::assertSame($resource, $capturedContext->getResource());
        self::assertSame(
            ['/quiqqer_oauth_test'],
            $capturedContext->getRequestedScopes()
        );
        self::assertStringContainsString('Customized MCP consent', $body);
        self::assertStringContainsString('User-specific MCP functions', $body);
        self::assertStringContainsString('Available MCP functions', $body);
        self::assertStringContainsString(
            'quiqqer-oauth-authorization-permissionType">Resource</span> <code>',
            $body
        );
        self::assertStringContainsString('project_&lt;information&gt;', $body);
        self::assertStringContainsString('project_update', $body);
    }

    public function testConsentUsesProjectLanguageAndRestoresPreviousLanguage(): void
    {
        $Project = QUI::getRewrite()->getProject();

        if (!$Project) {
            self::markTestSkipped('The integration test has no rewrite project.');
        }

        $projectLanguage = $Project->getLang();
        $Locale = QUI::getLocale();
        $previousLanguage = $Locale->getCurrent();
        $sessionLanguage = $projectLanguage === 'de' ? 'en' : 'de';
        $capturedLanguage = null;
        $listener = static function () use (&$capturedLanguage): void {
            $capturedLanguage = QUI::getLocale()->getCurrent();
        };
        $RestServer = RestServer::getCurrentInstance();
        $resource = Metadata::resource($RestServer);
        $clientId = $this->createAuthorizationClient($resource);
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => '/quiqqer_oauth_test',
            'state' => 'project-language-state',
            'code_challenge' => self::challenge(str_repeat('f', 64)),
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];

        Handler::setSessionUser(QUI::getUsers()->getSystemUser());
        $Locale->setCurrent($sessionLanguage);
        QUI::getEvents()->addEvent(
            'onQuiqqerOAuthConsentPresentation',
            $listener
        );

        try {
            $Response = $RestServer->getSlim()->handle(
                (new ServerRequest(
                    'GET',
                    '/api/oauth/authorize'
                ))->withQueryParams($query)
            );

            self::assertSame($projectLanguage, $capturedLanguage);
            self::assertSame($sessionLanguage, $Locale->getCurrent());
            self::assertStringContainsString(
                '<html lang="' . $projectLanguage . '">',
                (string)$Response->getBody()
            );
        } finally {
            QUI::getEvents()->removeEvent(
                'onQuiqqerOAuthConsentPresentation',
                $listener
            );
            $Locale->setCurrent($previousLanguage);
        }
    }

    private function createAuthorizationClient(
        string $resource,
        ?string $name = null,
        string $redirectUri = self::REDIRECT_URI
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
            [$redirectUri],
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

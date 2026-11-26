<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use OAuth2;
use Psr\Http\Message\ResponseInterface;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Consent\Context;
use QUI\OAuth\Consent\Presentation;
use QUI\OAuth\Metadata;
use QUI\OAuth\Middleware\ResourceController;
use QUI\OAuth\RestProvider;
use QUI\OAuth\Server;
use QUI\OAuth\Setup;
use QUI\Permissions\Permission;
use QUI\REST\Server as RestServer;
use QUI\Security\CsrfToken;
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
        $clientSecret = 'pkce-fixture+%20:ampersand&';
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
            ['user_id' => 99999999, 'client_secret' => $clientSecret],
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
            urlencode($clientId),
            urlencode($clientSecret),
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => $verifier
            ],
            redirectedAuthorization: true
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
            $clientSecret,
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
                $clientSecret,
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
            urlencode($clientId),
            urlencode($clientSecret),
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

    public function testTokenResponsesOmitScopeWhenNoScopeWasGranted(): void
    {
        $resource = Metadata::resource(RestServer::getCurrentInstance());
        $clientId = $this->createAuthorizationClient($resource);
        $client = Handler::getOAuthClient($clientId);
        $verifier = str_repeat('c', 64);
        $authorizationResponse = new OAuth2\Response();

        Server::getInstance()->getOAuth2Server()->handleAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                self::challenge($verifier),
                'state-without-scope',
                $resource,
                null
            ),
            $authorizationResponse,
            true,
            (string)QUI::getUsers()->getSystemUser()->getUUID()
        );
        parse_str(
            (string)parse_url(
                (string)$authorizationResponse->getHttpHeader('Location'),
                PHP_URL_QUERY
            ),
            $redirectQuery
        );
        self::assertNotEmpty($redirectQuery['code']);

        $TokenEndpoint = new QUI\OAuth\TokenEndpoint();
        $tokenResponse = $TokenEndpoint->handle($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'grant_type' => 'authorization_code',
                'code' => (string)$redirectQuery['code'],
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => $verifier
            ]
        ));
        $tokens = json_decode((string)$tokenResponse->getBody(), true);

        self::assertSame(200, $tokenResponse->getStatusCode());
        self::assertIsArray($tokens);
        self::assertArrayNotHasKey('scope', $tokens);

        $refreshResponse = $TokenEndpoint->handle($this->tokenRequest(
            $clientId,
            (string)$client['client_secret'],
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => (string)$tokens['refresh_token']
            ]
        ));
        $refreshedTokens = json_decode((string)$refreshResponse->getBody(), true);

        self::assertSame(200, $refreshResponse->getStatusCode());
        self::assertIsArray($refreshedTokens);
        self::assertArrayNotHasKey('scope', $refreshedTokens);
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

    public function testAdminCreatedPkceClientReachesLoginAndConsentForItsRegisteredResource(): void
    {
        $redirectUri = 'https://client.example.test/oauth/callback';
        $resource = 'https://resource.example.test/mcp';
        $created = $this->callClientAdminAjax('create', [
            'userId' => QUI::getUsers()->getSystemUser()->getId(),
            'scopeSettings' => '{}',
            'title' => self::TEST_PREFIX . 'manual-pkce',
            'authorization' => json_encode([
                'redirectUris' => [$redirectUri],
                'resources' => [$resource]
            ], JSON_THROW_ON_ERROR)
        ]);
        self::assertArrayNotHasKey('Exception', $created);
        self::assertIsString($created['result']);

        $query = [
            'response_type' => 'code',
            'client_id' => $created['result'],
            'redirect_uri' => $redirectUri,
            'state' => 'manual-client-state',
            'code_challenge' => self::challenge(str_repeat('p', 64)),
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];
        $RestServer = RestServer::getCurrentInstance();
        $Slim = $RestServer->getSlim();
        $Request = new ServerRequest('GET', self::TEST_BASE_HOST . '/api/oauth/authorize');

        Handler::setSessionUser(QUI::getUsers()->getNobody());
        $WrongResourceRequest = $Request->withQueryParams(array_replace($query, [
            'resource' => 'https://resource.example.test/other'
        ]));
        $WrongResourceResponse = $Slim->handle($WrongResourceRequest);

        self::assertSame(302, $WrongResourceResponse->getStatusCode());
        $errorLocation = $WrongResourceResponse->getHeaderLine('Location');
        parse_str((string)parse_url($errorLocation, PHP_URL_QUERY), $error);
        self::assertSame('invalid_target', $error['error'] ?? null);
        self::assertStringNotContainsString('id="quiqqer-oauth-login-control"', (string)$WrongResourceResponse->getBody());

        $Request = $Request->withQueryParams($query);
        $LoginResponse = $Slim->handle($Request);
        self::assertSame(200, $LoginResponse->getStatusCode());
        self::assertStringContainsString('id="quiqqer-oauth-login-control"', (string)$LoginResponse->getBody());

        Handler::setSessionUser(QUI::getUsers()->getSystemUser());
        $ConsentResponse = $Slim->handle($Request);
        self::assertSame(200, $ConsentResponse->getStatusCode());
        $consent = (string)$ConsentResponse->getBody();
        self::assertStringContainsString('quiqqer-oauth-authorization-card--consent', $consent);
        self::assertSame(1, preg_match('/name="_oauth_consent_token" value="([a-f0-9]{64})"/', $consent, $matches));

        $ApprovalRequest = (new ServerRequest('POST', '/api/oauth/authorize'))->withParsedBody($query + [
            '_oauth_consent_token' => $matches[1],
            'decision' => 'approve'
        ]);
        $callback = self::getContinuationUrl($Slim->handle($ApprovalRequest));
        self::assertStringStartsWith($redirectUri . '?', $callback);
        parse_str((string)parse_url($callback, PHP_URL_QUERY), $approved);
        self::assertSame('manual-client-state', $approved['state'] ?? null);
        self::assertNotEmpty($approved['code']);
    }

    public function testAdminAjaxShowsValidationErrorsAndSavesExactUrisAndSecret(): void
    {
        $configuration = [
            'redirectUris' => ['https://client.example.test/callback?a=1&b=2'],
            'resources' => ['https://resource.example.test/mcp?a=1&b=2']
        ];
        $invalidConfiguration = array_replace($configuration, ['resources' => ['http://resource.example.test/mcp']]);
        $createData = [
            'userId' => QUI::getUsers()->getSystemUser()->getId(),
            'scopeSettings' => '{}',
            'title' => self::TEST_PREFIX . 'admin-ajax'
        ];

        $invalid = $this->callClientAdminAjax('create', $createData + [
            'authorization' => json_encode($invalidConfiguration, JSON_THROW_ON_ERROR)
        ]);
        self::assertSame(400, $invalid['Exception']['code']);
        self::assertStringContainsString('HTTPS', $invalid['Exception']['message']);

        $created = $this->callClientAdminAjax('create', $createData + [
            'authorization' => json_encode($configuration, JSON_THROW_ON_ERROR)
        ]);
        self::assertArrayNotHasKey('Exception', $created);
        $client = ['clientId' => $created['result']];

        $before = $this->callClientAdminAjax('get', $client)['result'];
        self::assertSame($configuration + ['editable' => true], $before['authorization']);
        self::assertNotEmpty($before['client_secret']);

        $invalid = $this->callClientAdminAjax('update', $client + [
            'data' => json_encode(['authorization' => $invalidConfiguration], JSON_THROW_ON_ERROR)
        ]);
        self::assertSame(400, $invalid['Exception']['code']);
        self::assertSame($before, $this->callClientAdminAjax('get', $client)['result']);

        $configuration['redirectUris'][] = 'https://client.example.test/second-callback';
        $configuration['resources'][] = 'https://resource.example.test/second-mcp';
        $newSecret = 'test&secret';
        $updated = $this->callClientAdminAjax('update', $client + [
            'data' => json_encode([
                'authorization' => $configuration,
                'clientSecret' => $newSecret,
                'clientSecretIsToken' => true
            ], JSON_THROW_ON_ERROR)
        ]);
        self::assertArrayNotHasKey('Exception', $updated);

        $after = $this->callClientAdminAjax('get', $client)['result'];
        self::assertSame($configuration + ['editable' => true], $after['authorization']);
        self::assertSame('client_secret_basic', $after['token_endpoint_auth_method']);
        self::assertSame($newSecret, $after['client_secret']);
        self::assertEmpty($after['client_secret_is_token']);
    }

    public function testAdminAjaxKeepsRestClientsAndDynamicResourceBindingIntact(): void
    {
        $User = QUI::getUsers()->getSystemUser();
        $created = $this->callClientAdminAjax('create', [
            'userId' => $User->getId(),
            'scopeSettings' => '{}',
            'title' => self::TEST_PREFIX . 'legacy-rest'
        ]);
        self::assertArrayNotHasKey('Exception', $created);

        $restClient = $this->callClientAdminAjax('get', ['clientId' => $created['result']])['result'];
        self::assertNull($restClient['authorization']);
        self::assertNotEmpty($restClient['client_secret']);

        $dynamicId = Handler::createDynamicAuthorizationClient(
            $User,
            [],
            self::TEST_PREFIX . 'admin-dynamic',
            [self::REDIRECT_URI],
            ['authorization_code']
        );
        $client = ['clientId' => $dynamicId];
        $before = $this->callClientAdminAjax('get', $client)['result'];
        self::assertFalse($before['authorization']['editable']);
        self::assertNull($before['client_secret']);

        $updated = $this->callClientAdminAjax('update', $client + [
            'data' => json_encode([
                'authorization' => [
                    'redirectUris' => [self::REDIRECT_URI],
                    'resources' => [Metadata::resource(RestServer::getCurrentInstance())]
                ]
            ], JSON_THROW_ON_ERROR)
        ]);
        self::assertSame(400, $updated['Exception']['code']);
        self::assertSame($before, $this->callClientAdminAjax('get', $client)['result']);
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
        self::assertStringContainsString('quiqqer-oauth-authorization--consent', $body);
        self::assertStringContainsString('quiqqer-oauth-authorization-card--consent', $body);
        self::assertStringContainsString('quiqqer-oauth-authorization-content--consent', $body);
        self::assertStringContainsString('quiqqer-oauth-authorization-permissionList', $body);
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
            "form-action 'self';",
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

        $invalidPost = $post;
        $invalidPost['redirect_uri'] = 'https://unregistered.example.test/callback';
        $invalidResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('POST', '/api/oauth/authorize'))->withParsedBody($invalidPost)
        );
        self::assertSame(400, $invalidResponse->getStatusCode());
        self::assertFalse($invalidResponse->hasHeader('Location'));
        self::assertStringContainsString('redirect_uri_mismatch', (string)$invalidResponse->getBody());
        self::assertStringNotContainsString('http-equiv="refresh"', (string)$invalidResponse->getBody());

        $postResponse = $RestServer->getSlim()->handle(
            (new ServerRequest('POST', '/api/oauth/authorize'))->withParsedBody($post)
        );
        $callback = self::getContinuationUrl($postResponse);
        self::assertStringStartsWith(self::REDIRECT_URI . '?', $callback);
        parse_str((string)parse_url($callback, PHP_URL_QUERY), $redirectQuery);
        self::assertSame($query['state'], $redirectQuery['state'] ?? null);
        self::assertNotEmpty($redirectQuery['code']);

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
            "form-action 'self';",
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

        $callback = self::getContinuationUrl($postResponse);
        self::assertStringStartsWith($redirectUri . '?', $callback);
        parse_str((string)parse_url($callback, PHP_URL_QUERY), $redirectQuery);
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

    /**
     * @param array<string, mixed> $parameters
     * @return array<array-key, mixed>
     */
    private function callClientAdminAjax(string $action, array $parameters): array
    {
        require_once __DIR__ . '/../../ajax/client/' . $action . '.php';

        $Admin = QUI::getUsers()->get(QUI::conf('globals', 'rootuser'));

        return Permission::withUser(
            $Admin,
            static fn(): array => (new QUI\Ajax())->callRequestFunction(
                'package_quiqqer_oauth-server_ajax_client_' . $action,
                $parameters + ['_csrf' => CsrfToken::get()]
            )
        );
    }

    private function authorizationRequest(
        string $clientId,
        ?string $challenge,
        string $state,
        string $resource,
        ?string $scope = '/quiqqer_oauth_test'
    ): OAuth2\Request {
        $query = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'state' => $state,
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ];

        if ($scope !== null) {
            $query['scope'] = $scope;
        }

        if ($challenge !== null) {
            $query['code_challenge'] = $challenge;
        }

        return new OAuth2\Request($query);
    }

    /**
     * @param array<string, mixed> $body
     */
    private function tokenRequest(
        string $clientId,
        string $clientSecret,
        array $body,
        bool $redirectedAuthorization = false
    ): ServerRequest {
        $authorization = 'Basic ' . base64_encode($clientId . ':' . $clientSecret);
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded'];
        $server = [];

        if ($redirectedAuthorization) {
            $server['REDIRECT_HTTP_AUTHORIZATION'] = $authorization;
        } else {
            $headers['Authorization'] = $authorization;
        }

        return (new ServerRequest(
            'POST',
            '/api/oauth/token',
            $headers,
            null,
            '1.1',
            $server
        ))->withParsedBody($body);
    }

    private static function challenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private static function getContinuationUrl(ResponseInterface $Response): string
    {
        self::assertSame(200, $Response->getStatusCode());
        self::assertFalse($Response->hasHeader('Location'));
        self::assertSame('text/html; charset=utf-8', $Response->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $Response->getHeaderLine('Cache-Control'));
        self::assertSame('no-referrer', $Response->getHeaderLine('Referrer-Policy'));
        self::assertStringContainsString(
            "form-action 'self';",
            $Response->getHeaderLine('Content-Security-Policy')
        );

        $body = (string)$Response->getBody();
        self::assertSame(1, preg_match('/http-equiv="refresh" content="0;url=([^"]+)"/', $body, $matches));
        self::assertStringContainsString('href="' . $matches[1] . '"', $body);

        return html_entity_decode($matches[1], ENT_QUOTES, 'UTF-8');
    }

    private static function redirectError(OAuth2\Response $Response): ?string
    {
        $location = $Response->getHttpHeader('Location');
        parse_str((string)parse_url((string)$location, PHP_URL_QUERY), $query);

        return isset($query['error']) && is_string($query['error']) ? $query['error'] : null;
    }
}

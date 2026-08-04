<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use OAuth2;
use QUI;
use QUI\OAuth\ClientConfiguration;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\DynamicClientRegistrationEndpoint;
use QUI\OAuth\DynamicResourceTrustPolicy;
use QUI\OAuth\Metadata;
use QUI\OAuth\RestProvider;
use QUI\OAuth\Server;
use QUI\OAuth\StorageFactory;
use QUI\REST\Server as RestServer;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

final class DynamicClientRegistrationTest extends OAuthDatabaseTestCase
{
    private const BASE_HOST = 'https://oauth.example.test';
    private const REDIRECT_URI = 'http://127.0.0.1:43123/callback/codex';
    private const SCOPE = 'service.execute';

    private mixed $previousDynamicRegistration;
    private mixed $previousReusableDynamicRefreshTokens;
    private ?array $previousVhosts;

    protected function setUp(): void
    {
        parent::setUp();

        $RestServer = new RestServer([
            'basePath' => '/api',
            'baseHost' => self::BASE_HOST
        ]);
        (new RestProvider())->register($RestServer);

        $ServerProperty = new \ReflectionProperty(
            RestServer::class,
            'currentInstance'
        );
        $ServerProperty->setValue(null, $RestServer);

        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $this->previousDynamicRegistration = $Config->getValue(
            'general',
            'dynamic_client_registration'
        );
        $this->previousReusableDynamicRefreshTokens = $Config->getValue(
            'general',
            'reuse_refresh_tokens_for_dynamic_clients'
        );
        $this->previousVhosts = QUI::$vhosts;
        $Config->setValue('general', 'dynamic_client_registration', 1);
        $Config->setValue(
            'general',
            'reuse_refresh_tokens_for_dynamic_clients',
            1
        );
    }

    protected function tearDown(): void
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $Config->setValue(
            'general',
            'dynamic_client_registration',
            $this->previousDynamicRegistration
        );
        $Config->setValue(
            'general',
            'reuse_refresh_tokens_for_dynamic_clients',
            $this->previousReusableDynamicRefreshTokens
        );
        QUI::$vhosts = $this->previousVhosts;

        parent::tearDown();
    }

    public function testCodexCanRegisterAuthorizeAndRefreshAsPublicClient(): void
    {
        $metadata = Metadata::authorizationServer(
            RestServer::getCurrentInstance()
        );
        self::assertSame(
            self::BASE_HOST . '/api/oauth/register',
            $metadata['registration_endpoint'] ?? null
        );

        $registration = $this->registerClient();
        self::assertSame(201, $registration->getStatusCode());
        self::assertSame('no-store', $registration->getHeaderLine('Cache-Control'));

        $registered = json_decode((string)$registration->getBody(), true);
        self::assertIsArray($registered);
        self::assertNotEmpty($registered['client_id']);
        self::assertArrayNotHasKey('client_secret', $registered);
        self::assertSame('none', $registered['token_endpoint_auth_method']);
        self::assertSame(
            [self::REDIRECT_URI],
            $registered['redirect_uris']
        );
        self::assertSame(self::SCOPE, $registered['scope']);

        $clientId = (string)$registered['client_id'];
        $client = Handler::getOAuthClient($clientId);
        self::assertNull($client['client_secret']);
        self::assertSame(
            'authorization_code refresh_token',
            $client['grant_types']
        );
        self::assertTrue(ClientConfiguration::isDynamicRegistration(
            $client['allowed_resources'] ?? null
        ));
        self::assertSame([], ClientConfiguration::decodeResources(
            $client['allowed_resources'] ?? null
        ));

        $resource = self::BASE_HOST . '/mcp';
        $verifier = str_repeat('d', 64);
        $OAuthServer = Server::getInstance()->getOAuth2Server();
        $authorizationResponse = new OAuth2\Response();
        $OAuthServer->handleAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                $resource,
                self::challenge($verifier)
            ),
            $authorizationResponse,
            true,
            (string)QUI::getUsers()->getSystemUser()->getUUID()
        );

        self::assertSame(302, $authorizationResponse->getStatusCode());
        $location = (string)$authorizationResponse->getHttpHeader('Location');
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        self::assertNotEmpty($query['code']);

        $client = Handler::getOAuthClient($clientId);
        self::assertSame([$resource], ClientConfiguration::decodeResources(
            $client['allowed_resources'] ?? null
        ));

        $tokenResponse = RestServer::getCurrentInstance()->getSlim()->handle(
            $this->tokenRequest([
                'grant_type' => 'authorization_code',
                'client_id' => $clientId,
                'code' => (string)$query['code'],
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => $verifier,
                'resource' => $resource
            ])
        );
        $tokens = json_decode((string)$tokenResponse->getBody(), true);
        self::assertSame(200, $tokenResponse->getStatusCode());
        self::assertIsArray($tokens);
        self::assertNotEmpty($tokens['access_token']);
        self::assertNotEmpty($tokens['refresh_token']);

        $Storage = StorageFactory::create();
        self::assertSame(
            $resource,
            $Storage->getAccessToken((string)$tokens['access_token'])['resource']
        );

        $refreshResponse = RestServer::getCurrentInstance()->getSlim()->handle(
            $this->tokenRequest([
                'grant_type' => 'refresh_token',
                'client_id' => $clientId,
                'refresh_token' => (string)$tokens['refresh_token'],
                'resource' => $resource
            ])
        );
        $refreshed = json_decode((string)$refreshResponse->getBody(), true);
        self::assertSame(200, $refreshResponse->getStatusCode());
        self::assertIsArray($refreshed);
        self::assertNotEmpty($refreshed['access_token']);
        self::assertArrayNotHasKey('refresh_token', $refreshed);

        $secondRefreshResponse = RestServer::getCurrentInstance()
            ->getSlim()
            ->handle($this->tokenRequest([
                'grant_type' => 'refresh_token',
                'client_id' => $clientId,
                'refresh_token' => (string)$tokens['refresh_token'],
                'resource' => $resource
            ]));
        $secondRefresh = json_decode(
            (string)$secondRefreshResponse->getBody(),
            true
        );
        self::assertSame(200, $secondRefreshResponse->getStatusCode());
        self::assertIsArray($secondRefresh);
        self::assertNotEmpty($secondRefresh['access_token']);
        self::assertNotSame(
            $refreshed['access_token'],
            $secondRefresh['access_token']
        );
        self::assertArrayNotHasKey('refresh_token', $secondRefresh);

        $storedRefreshToken = $Storage->getRefreshToken(
            (string)$tokens['refresh_token']
        );
        self::assertIsArray($storedRefreshToken);
        self::assertEmpty($storedRefreshToken['replaced_by']);

        $revokeResponse = RestServer::getCurrentInstance()
            ->getSlim()
            ->handle((new ServerRequest(
                'POST',
                '/api/oauth/revoke',
                ['Content-Type' => 'application/x-www-form-urlencoded']
            ))->withParsedBody([
                'client_id' => $clientId,
                'token' => (string)$tokens['refresh_token'],
                'token_type_hint' => 'refresh_token'
            ]));
        self::assertSame(200, $revokeResponse->getStatusCode());

        $revokedRefreshResponse = RestServer::getCurrentInstance()
            ->getSlim()
            ->handle($this->tokenRequest([
                'grant_type' => 'refresh_token',
                'client_id' => $clientId,
                'refresh_token' => (string)$tokens['refresh_token'],
                'resource' => $resource
            ]));
        $revokedRefresh = json_decode(
            (string)$revokedRefreshResponse->getBody(),
            true
        );
        self::assertSame(400, $revokedRefreshResponse->getStatusCode());
        self::assertIsArray($revokedRefresh);
        self::assertSame('invalid_grant', $revokedRefresh['error'] ?? null);
    }

    public function testDynamicClientIsBoundToOneSameOriginResource(): void
    {
        $registered = json_decode(
            (string)$this->registerClient()->getBody(),
            true
        );
        self::assertIsArray($registered);
        $clientId = (string)$registered['client_id'];
        $OAuthServer = Server::getInstance()->getOAuth2Server();
        $offOrigin = new OAuth2\Response();

        self::assertFalse($OAuthServer->validateAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                'https://other.example.test/mcp',
                self::challenge(str_repeat('e', 64))
            ),
            $offOrigin
        ));
        self::assertSame('invalid_target', self::redirectError($offOrigin));
        self::assertSame([], ClientConfiguration::decodeResources(
            Handler::getOAuthClient($clientId)['allowed_resources'] ?? null
        ));

        $resource = self::BASE_HOST . '/mcp';
        $allowed = new OAuth2\Response();
        self::assertTrue($OAuthServer->validateAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                $resource,
                self::challenge(str_repeat('f', 64))
            ),
            $allowed
        ));

        $otherResource = new OAuth2\Response();
        self::assertFalse($OAuthServer->validateAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                self::BASE_HOST . '/other-mcp',
                self::challenge(str_repeat('g', 64))
            ),
            $otherResource
        ));
        self::assertSame(
            'invalid_target',
            self::redirectError($otherResource)
        );
    }

    public function testConfiguredVhostResourceIsReevaluatedForTokens(): void
    {
        $resource = 'https://mcp.example.test/mcp';
        QUI::$vhosts = [
            'mcp.example.test' => [
                'project' => 'example',
                'lang' => 'en'
            ]
        ];
        $registered = json_decode(
            (string)$this->registerClient()->getBody(),
            true
        );
        self::assertIsArray($registered);
        $clientId = (string)$registered['client_id'];
        $verifier = str_repeat('h', 64);
        $OAuthServer = Server::getInstance()->getOAuth2Server();
        $authorizationResponse = new OAuth2\Response();

        $OAuthServer->handleAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                $resource,
                self::challenge($verifier)
            ),
            $authorizationResponse,
            true,
            (string)QUI::getUsers()->getSystemUser()->getUUID()
        );

        self::assertSame(302, $authorizationResponse->getStatusCode());
        self::assertSame([$resource], ClientConfiguration::decodeResources(
            Handler::getOAuthClient($clientId)['allowed_resources'] ?? null
        ));
        $location = (string)$authorizationResponse->getHttpHeader('Location');
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        self::assertNotEmpty($query['code']);

        QUI::$vhosts = [];
        $authorizationAfterRemoval = new OAuth2\Response();
        self::assertFalse($OAuthServer->validateAuthorizeRequest(
            $this->authorizationRequest(
                $clientId,
                $resource,
                self::challenge(str_repeat('i', 64))
            ),
            $authorizationAfterRemoval
        ));
        self::assertSame(
            'invalid_target',
            self::redirectError($authorizationAfterRemoval)
        );

        $tokenResponse = RestServer::getCurrentInstance()->getSlim()->handle(
            $this->tokenRequest([
                'grant_type' => 'authorization_code',
                'client_id' => $clientId,
                'code' => (string)$query['code'],
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => $verifier,
                'resource' => $resource
            ])
        );
        $payload = json_decode((string)$tokenResponse->getBody(), true);
        self::assertSame(400, $tokenResponse->getStatusCode());
        self::assertIsArray($payload);
        self::assertSame('invalid_target', $payload['error'] ?? null);
    }

    public function testTrustedVhostOriginsIncludeAliasesButNotWildcards(): void
    {
        QUI::$vhosts = [
            'primary.example.test' => [
                'project' => 'example',
                'lang' => 'en',
                'httpshost' => 'secure.example.test',
                'de' => 'de.example.test'
            ],
            '*.wildcard.example.test' => [
                'project' => 'wildcard',
                'lang' => 'en'
            ]
        ];

        self::assertSame(
            [
                'https://de.example.test',
                'https://primary.example.test',
                'https://secure.example.test'
            ],
            DynamicResourceTrustPolicy::getTrustedVhostOrigins()
        );
    }

    /**
     * @dataProvider invalidRegistrationProvider
     * @param array<string, mixed> $overrides
     */
    public function testRegistrationRejectsUnsafeMetadata(
        array $overrides,
        string $expectedError
    ): void {
        $response = $this->registerClient($overrides);
        $payload = json_decode((string)$response->getBody(), true);

        self::assertSame(400, $response->getStatusCode());
        self::assertIsArray($payload);
        self::assertSame($expectedError, $payload['error'] ?? null);
        self::assertNotEmpty($payload['error_description']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidRegistrationProvider(): iterable
    {
        yield 'confidential client' => [
            ['token_endpoint_auth_method' => 'client_secret_basic'],
            'invalid_client_metadata'
        ];
        yield 'client credentials grant' => [
            ['grant_types' => ['client_credentials']],
            'invalid_client_metadata'
        ];
        yield 'implicit response' => [
            ['response_types' => ['token']],
            'invalid_client_metadata'
        ];
        yield 'remote insecure redirect' => [
            ['redirect_uris' => ['http://client.example.test/callback']],
            'invalid_redirect_uri'
        ];
        yield 'redirect with fragment' => [
            ['redirect_uris' => ['https://client.example.test/callback#token']],
            'invalid_redirect_uri'
        ];
        yield 'invalid scope token' => [
            ['scope' => 'valid invalid"scope'],
            'invalid_client_metadata'
        ];
        yield 'invalid scope separator' => [
            ['scope' => "valid\tinvalid"],
            'invalid_client_metadata'
        ];
    }

    public function testDisabledRegistrationIsNotAdvertised(): void
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $Config->setValue('general', 'dynamic_client_registration', 0);
        $metadata = Metadata::authorizationServer(
            RestServer::getCurrentInstance()
        );

        self::assertArrayNotHasKey('registration_endpoint', $metadata);
        self::assertSame(404, $this->registerClient()->getStatusCode());
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function registerClient(
        array $overrides = []
    ): \Psr\Http\Message\ResponseInterface {
        $metadata = array_replace([
            'client_name' => self::TEST_PREFIX . 'Codex',
            'redirect_uris' => [self::REDIRECT_URI],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'application_type' => 'native',
            'scope' => self::SCOPE
        ], $overrides);
        $body = json_encode(
            $metadata,
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
        );

        return (new DynamicClientRegistrationEndpoint())->handle(
            new ServerRequest(
                'POST',
                '/api/oauth/register',
                ['Content-Type' => 'application/json'],
                $body
            )
        );
    }

    private function authorizationRequest(
        string $clientId,
        string $resource,
        string $challenge
    ): OAuth2\Request {
        return new OAuth2\Request([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => self::SCOPE,
            'state' => bin2hex(random_bytes(16)),
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
            'resource' => $resource
        ]);
    }

    /**
     * @param array<string, string> $body
     */
    private function tokenRequest(array $body): ServerRequest
    {
        return (new ServerRequest(
            'POST',
            '/api/oauth/token',
            ['Content-Type' => 'application/x-www-form-urlencoded']
        ))->withParsedBody($body);
    }

    private static function challenge(string $verifier): string
    {
        return rtrim(strtr(
            base64_encode(hash('sha256', $verifier, true)),
            '+/',
            '-_'
        ), '=');
    }

    private static function redirectError(OAuth2\Response $Response): ?string
    {
        $location = $Response->getHttpHeader('Location');
        parse_str((string)parse_url((string)$location, PHP_URL_QUERY), $query);

        return isset($query['error']) && is_string($query['error'])
            ? $query['error']
            : null;
    }
}

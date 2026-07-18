<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use OAuth2;
use PDO;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Middleware\InvalidRequestException;
use QUI\OAuth\Middleware\ResourceController;
use QUI\OAuth\Server;
use QUI\OAuth\Setup;
use QUI\OAuth\Storage;
use QUI\OAuth\StorageFactory;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

class TokenAndResourceTest extends OAuthDatabaseTestCase
{
    public function testNativePdoBoundaryAndStorageTokenLifecycle(): void
    {
        $nativeConnection = self::getConnection()->getNativeConnection();
        self::assertInstanceOf(PDO::class, $nativeConnection);

        $Storage = StorageFactory::create();
        $clientId = self::createClient([
            '/quiqqer_oauth_test' => [
                'active' => true,
                'unlimitedCalls' => true
            ]
        ]);
        $client = Handler::getOAuthClient($clientId);

        self::assertTrue($Storage->checkClientCredentials($clientId, $client['client_secret']));
        self::assertFalse($Storage->checkClientCredentials($clientId, 'wrong-secret'));
        self::assertFalse($Storage->checkClientCredentials(strtoupper($clientId), $client['client_secret']));
        self::assertFalse($Storage->isPublicClient($clientId));
        self::assertSame($clientId, $Storage->getClientDetails($clientId)['client_id']);

        $accessToken = 'access-' . bin2hex(random_bytes(8));
        self::assertTrue($Storage->setAccessToken(
            $accessToken,
            $clientId,
            $client['user_id'],
            time() + 3600,
            '/quiqqer_oauth_test'
        ));
        self::assertSame($clientId, $Storage->getAccessToken($accessToken)['client_id']);
        self::assertSame($clientId, Handler::getOAuthClientByAccessToken($accessToken)['client_id']);
        self::assertTrue($Storage->unsetAccessToken($accessToken));
        self::assertFalse($Storage->getAccessToken($accessToken));

        $refreshToken = 'refresh-' . bin2hex(random_bytes(8));
        self::assertTrue($Storage->setRefreshToken(
            $refreshToken,
            $clientId,
            $client['user_id'],
            time() + 7200,
            '/quiqqer_oauth_test'
        ));
        self::assertSame($clientId, $Storage->getRefreshToken($refreshToken)['client_id']);

        $RefreshServer = new OAuth2\Server($Storage);
        $RefreshServer->addGrantType(new OAuth2\GrantType\RefreshToken($Storage));
        $refreshResponse = $RefreshServer->handleTokenRequest(new OAuth2\Request(
            [],
            ['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken],
            [],
            [],
            [],
            [
                'REQUEST_METHOD' => 'POST',
                'PHP_AUTH_USER' => $clientId,
                'PHP_AUTH_PW' => $client['client_secret']
            ]
        ));

        self::assertSame(200, $refreshResponse->getStatusCode());
        self::assertArrayHasKey('access_token', $refreshResponse->getParameters());
    }

    public function testServerIssuesAndRejectsAccessTokens(): void
    {
        $clientId = self::createClient([
            '/quiqqer_oauth_test' => [
                'active' => true,
                'unlimitedCalls' => true
            ]
        ]);
        $client = Handler::getOAuthClient($clientId);
        $OAuthServer = Server::getInstance()->getOAuth2Server();

        $response = $OAuthServer->handleTokenRequest($this->clientCredentialsRequest(
            $clientId,
            (string)$client['client_secret']
        ));
        self::assertSame(200, $response->getStatusCode());
        $parameters = $response->getParameters();
        self::assertArrayHasKey('access_token', $parameters);
        self::assertSame('Bearer', $parameters['token_type']);
        self::assertGreaterThan(time(), $parameters['expires_in'] + time() - 1);

        $accessToken = (string)$parameters['access_token'];
        self::assertTrue($OAuthServer->verifyResourceRequest(new OAuth2\Request([
            'access_token' => $accessToken
        ])));

        $Storage = new Storage(self::getConnection()->getNativeConnection());
        self::assertTrue($Storage->unsetAccessToken($accessToken));
        self::assertFalse($OAuthServer->verifyResourceRequest(new OAuth2\Request([
            'access_token' => $accessToken
        ])));
        self::assertFalse($OAuthServer->verifyResourceRequest(new OAuth2\Request([
            'access_token' => 'invalid-access-token'
        ])));

        $expiredToken = 'expired-' . bin2hex(random_bytes(8));
        $Storage->setAccessToken($expiredToken, $clientId, $client['user_id'], time() - 60, null);
        self::assertFalse($OAuthServer->verifyResourceRequest(new OAuth2\Request([
            'access_token' => $expiredToken
        ])));

        $invalidResponse = $OAuthServer->handleTokenRequest($this->clientCredentialsRequest(
            $clientId,
            'invalid-client-secret'
        ));
        self::assertSame(400, $invalidResponse->getStatusCode());
        self::assertSame('invalid_client', $invalidResponse->getParameters()['error']);
    }

    public function testResourceControllerEnforcesScopeAndRateLimit(): void
    {
        $scope = '/quiqqer_oauth_test';
        $clientId = self::createClient([
            $scope => [
                'active' => true,
                'unlimitedCalls' => false,
                'maxCalls' => 1,
                'maxCallsType' => 'absolute'
            ]
        ], true);
        $client = Handler::getOAuthClient($clientId);
        $request = new ServerRequest('GET', '/resource', [
            'Authorization' => 'Bearer ' . $client['client_secret']
        ]);
        $Controller = Server::getInstance()->getOAuth2Server()->getResourceController();

        self::assertInstanceOf(ResourceController::class, $Controller);
        $Controller->verify($scope, $request);
        self::assertSame((int)$client['user_id'], Handler::getSessionUser()->getId());

        $limit = Handler::getClientLimits($clientId, $scope)[$scope];
        self::assertSame(1, (int)$limit['total_usage_count']);
        self::assertSame(1, (int)$limit['interval_usage_count']);

        try {
            $Controller->verify($scope, $request);
            self::fail('The absolute request limit must be enforced.');
        } catch (InvalidRequestException $Exception) {
            self::assertSame(429, $Exception->getCode());
            self::assertSame('query_limit_reached', $Exception->getMessage());
        }

        try {
            $Controller->verify('/not-an-installed-scope', $request);
            self::fail('Unknown scopes must be rejected.');
        } catch (InvalidRequestException $Exception) {
            self::assertSame(403, $Exception->getCode());
            self::assertSame('insufficient_scope', $Exception->getMessage());
        }
    }

    public function testResourceControllerAcceptsAndRejectsRegularAccessTokens(): void
    {
        $scope = '/quiqqer_oauth_test';
        $clientId = self::createClient([
            $scope => [
                'active' => true,
                'unlimitedCalls' => true,
                'maxCalls' => 0,
                'maxCallsType' => 'absolute'
            ]
        ]);
        $client = Handler::getOAuthClient($clientId);
        $OAuthServer = Server::getInstance()->getOAuth2Server();
        $tokenResponse = $OAuthServer->handleTokenRequest($this->clientCredentialsRequest(
            $clientId,
            (string)$client['client_secret']
        ));
        $accessToken = (string)$tokenResponse->getParameters()['access_token'];
        $Controller = $OAuthServer->getResourceController();

        $Controller->verify(
            $scope,
            (new ServerRequest('GET', '/resource'))->withQueryParams([
                'access_token' => $accessToken
            ])
        );
        self::assertSame((int)$client['user_id'], Handler::getSessionUser()->getId());

        try {
            $Controller->verify(
                $scope,
                (new ServerRequest('GET', '/resource'))->withQueryParams([
                    'access_token' => 'invalid-access-token'
                ])
            );
            self::fail('Invalid access tokens must be rejected.');
        } catch (InvalidRequestException $Exception) {
            self::assertSame(401, $Exception->getCode());
            self::assertSame('invalid_token', $Exception->getMessage());
        }
    }

    public function testResourceControllerCoversAllLimitIntervalsAndInactiveScopes(): void
    {
        $scopeSettings = [
            '/help' => [
                'active' => true,
                'unlimitedCalls' => true,
                'maxCalls' => 0,
                'maxCallsType' => 'absolute'
            ],
            '/blz-test' => $this->limitedScope('minute'),
            '/generate' => $this->limitedScope('hour'),
            '/invoice/create' => $this->limitedScope('day'),
            '/menus/get' => $this->limitedScope('month'),
            '/menus/update' => $this->limitedScope('year'),
            '/menus/delete' => [
                'active' => false,
                'unlimitedCalls' => true,
                'maxCalls' => 0,
                'maxCallsType' => 'absolute'
            ]
        ];
        $clientId = self::createClient($scopeSettings, true);
        $client = Handler::getOAuthClient($clientId);
        $request = new ServerRequest('GET', '/resource', [
            'Authorization' => 'Bearer ' . $client['client_secret']
        ]);
        $Controller = Server::getInstance()->getOAuth2Server()->getResourceController();
        $limitsTable = QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_access_limits'));

        $Controller->verify('/help', $request);

        foreach (['/blz-test', '/generate', '/invoice/create', '/menus/get', '/menus/update'] as $scope) {
            self::getConnection()->update(
                $limitsTable,
                ['interval_usage_count' => 3, 'first_usage' => time() - 70000000],
                ['client_id' => $clientId, 'scope' => $scope]
            );
            $Controller->verify($scope, $request);
            self::assertSame(1, (int)Handler::getClientLimits($clientId, $scope)[$scope]['interval_usage_count']);
        }

        try {
            $Controller->verify('/menus/delete', $request);
            self::fail('Inactive scopes must be rejected.');
        } catch (InvalidRequestException $Exception) {
            self::assertSame(403, $Exception->getCode());
        }

        self::getConnection()->delete($limitsTable, [
            'client_id' => $clientId,
            'scope' => '/help'
        ]);

        try {
            $Controller->verify('/help', $request);
            self::fail('Scopes without limit metadata must be rejected.');
        } catch (InvalidRequestException $Exception) {
            self::assertSame(403, $Exception->getCode());
        }
    }

    public function testScopeParsingSupportsRequiredOptionalAndInvalidPaths(): void
    {
        self::assertSame('/check[/{iban}]', ResourceController::parseScopeFromEndpoint('/check'));
        self::assertSame('/check[/{iban}]', ResourceController::parseScopeFromEndpoint('/check/DE44500105175407324931'));
        self::assertSame('/hello/{name}', ResourceController::parseScopeFromEndpoint('/hello/Ada'));
        self::assertFalse(ResourceController::parseScopeFromEndpoint('/missing/route'));
    }

    public function testStorageReturnsRealQuiqqerUserDetails(): void
    {
        $Storage = new Storage(self::getConnection()->getNativeConnection());
        $userRow = self::getConnection()->createQueryBuilder()
            ->select('uuid', 'username')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\Users\Manager::table()))
            ->where("username <> ''")
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($userRow);
        $details = $Storage->getUserDetails((string)$userRow['username']);

        self::assertIsArray($details);
        self::assertSame($userRow['uuid'], $details['user_id']);
        self::assertFalse($Storage->getUserDetails(self::TEST_PREFIX . 'missing-user'));
    }

    private function clientCredentialsRequest(string $clientId, string $clientSecret): OAuth2\Request
    {
        return new OAuth2\Request(
            [],
            ['grant_type' => 'client_credentials'],
            [],
            [],
            [],
            [
                'REQUEST_METHOD' => 'POST',
                'PHP_AUTH_USER' => $clientId,
                'PHP_AUTH_PW' => $clientSecret
            ]
        );
    }

    /**
     * @return array{active: true, unlimitedCalls: false, maxCalls: int, maxCallsType: string}
     */
    private function limitedScope(string $type): array
    {
        return [
            'active' => true,
            'unlimitedCalls' => false,
            'maxCalls' => 3,
            'maxCallsType' => $type
        ];
    }
}

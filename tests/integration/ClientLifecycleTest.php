<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use QUI;
use QUI\Cache\Exception as CacheException;
use QUI\Cache\LongTermCache;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Exception as OAuthException;
use QUI\OAuth\Setup;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

class ClientLifecycleTest extends OAuthDatabaseTestCase
{
    public function testClientCrudLimitsAndCacheInvalidation(): void
    {
        $scope = '/quiqqer_oauth_test';
        $clientId = self::createClient([
            $scope => [
                'active' => true,
                'unlimitedCalls' => false,
                'maxCalls' => 2,
                'maxCallsType' => 'minute'
            ]
        ], true);

        $client = Handler::getOAuthClient($clientId);
        self::assertSame($clientId, $client['client_id']);
        self::assertSame(1, (int)$client['client_secret_is_token']);
        self::assertSame($scope, $client['scope']);
        self::assertCount(1, Handler::getOAuthClientByUser(QUI::getUsers()->getSystemUser(), $clientId));
        self::assertNotEmpty(Handler::getOAuthClientsByUser(QUI::getUsers()->getSystemUser()));
        self::assertSame(1, Handler::getNumberOfPermanentAccessTokens(QUI::getUsers()->getSystemUser()));
        self::assertCount(1, Handler::getOAuthClientsWithPermanentAccessToken(QUI::getUsers()->getSystemUser()));

        $secret = (string)$client['client_secret'];
        self::assertFalse(Handler::getOAuthClientByAccessToken($secret));
        self::assertSame(
            $clientId,
            Handler::getOAuthClientByAccessToken($secret, true)['client_id']
        );

        $request = new ServerRequest('GET', '/resource', ['Authorization' => 'Bearer ' . $secret]);
        self::assertSame(
            $clientId,
            Handler::getOAuthClientDataByRequestWithClientSecretAsToken($request)['client_id']
        );
        self::assertIsArray(LongTermCache::get(self::cacheName($secret)));

        $limits = Handler::getClientLimits($clientId);
        self::assertArrayHasKey($scope, $limits);
        self::assertFalse($limits[$scope]['queryLimitReached']);

        self::getConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_access_limits')),
            [
                'interval_usage_count' => 2,
                'total_usage_count' => 5,
                'first_usage' => 100,
                'last_usage' => 200
            ],
            ['client_id' => $clientId, 'scope' => $scope]
        );

        self::assertTrue(Handler::getClientLimits($clientId, $scope)[$scope]['queryLimitReached']);
        Handler::resetClientLimits($clientId);
        $resetLimits = Handler::getClientLimits($clientId, $scope)[$scope];
        self::assertSame(0, (int)$resetLimits['interval_usage_count']);
        self::assertSame(0, (int)$resetLimits['first_usage']);
        self::assertSame(0, (int)$resetLimits['last_usage']);

        Handler::updateOAuthClient($clientId, [
            'title' => self::TEST_PREFIX . 'updated',
            'scope_restrictions' => [
                $scope => [
                    'active' => true,
                    'unlimitedCalls' => true,
                    'maxCalls' => 0,
                    'maxCallsType' => 'absolute'
                ],
                '/not-an-installed-scope' => [
                    'active' => true,
                    'unlimitedCalls' => true
                ]
            ],
            'clientSecretIsToken' => false
        ]);

        $updated = Handler::getOAuthClient($clientId);
        self::assertSame(self::TEST_PREFIX . 'updated', $updated['name']);
        self::assertSame(0, (int)$updated['client_secret_is_token']);
        self::assertStringNotContainsString('/not-an-installed-scope', (string)$updated['scope_restrictions']);

        self::resetLongTermCacheRuntime();
        $this->expectException(CacheException::class);
        LongTermCache::get(self::cacheName($secret));
    }

    public function testSecretGenerationEmptyResultsAndRelevantErrors(): void
    {
        $secret = Handler::generatePassword(96);
        self::assertSame(96, strlen($secret));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9()\[\]{}?!%&\/=*+~,.;:_-]+$/', $secret);
        self::assertNotSame($secret, Handler::generatePassword(96));

        self::assertSame([], Handler::getOAuthClientByUser(QUI::getUsers()->getSystemUser(), 'missing-client'));
        self::assertFalse(Handler::getOAuthClientByAccessToken('invalid-token'));
        self::assertNull(
            Handler::getOAuthClientDataByRequestWithClientSecretAsToken(new ServerRequest('GET', '/resource'))
        );
        self::assertSame(1, Handler::getMaxNumberOfPermanentAccessTokens(QUI::getUsers()->getSystemUser()));

        try {
            Handler::getOAuthClient('missing-client');
            self::fail('Unknown OAuth client must be rejected.');
        } catch (OAuthException $Exception) {
            self::assertSame(404, $Exception->getCode());
        }

        self::createClient();
    }

    public function testNobodyCannotOwnAnOauthClient(): void
    {
        $this->expectException(QUI\Exception::class);
        Handler::createOAuthClient(QUI::getUsers()->getNobody(), [], self::TEST_PREFIX . 'nobody');
    }

    public function testClientRemovalDeletesAllDependentRows(): void
    {
        $clientId = self::createClient([
            '/quiqqer_oauth_test' => [
                'active' => true,
                'unlimitedCalls' => true
            ]
        ]);
        $client = Handler::getOAuthClient($clientId);
        $accessToken = 'test-access-' . bin2hex(random_bytes(8));

        self::getConnection()->insert(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_access_tokens')),
            [
                'access_token' => $accessToken,
                'client_id' => $clientId,
                'user_id' => $client['user_id'],
                'expires' => date('Y-m-d H:i:s', time() + 3600),
                'scope' => '/quiqqer_oauth_test'
            ]
        );

        self::assertSame($clientId, Handler::getOAuthClientByAccessToken($accessToken)['client_id']);
        Handler::removeOAuthClient($clientId);

        foreach (Setup::getClientTables() as $table) {
            $count = self::getConnection()->createQueryBuilder()
                ->select('COUNT(*)')
                ->from(QUI\Utils\Doctrine::quoteIdentifier($table))
                ->where('client_id = :clientId')
                ->setParameter('clientId', $clientId)
                ->executeQuery()
                ->fetchOne();

            self::assertSame(0, (int)$count);
        }
    }

    public function testCleanupOnlyDeletesTokensExpiredForAtLeastOneDay(): void
    {
        $clientId = self::createClient();
        $client = Handler::getOAuthClient($clientId);
        $table = QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_access_tokens'));
        $oldToken = 'old-' . bin2hex(random_bytes(8));
        $recentToken = 'recent-' . bin2hex(random_bytes(8));

        $tokensByExpiration = [
            $oldToken => time() - 90000,
            $recentToken => time() - 3600
        ];

        foreach ($tokensByExpiration as $token => $expires) {
            self::getConnection()->insert($table, [
                'access_token' => $token,
                'client_id' => $clientId,
                'user_id' => $client['user_id'],
                'expires' => date('Y-m-d H:i:s', $expires),
                'scope' => null
            ]);
        }

        Handler::cleanupAccessTokens();

        self::assertFalse(
            self::getConnection()->fetchOne(
                'SELECT access_token FROM ' . $table . ' WHERE access_token = ?',
                [$oldToken]
            )
        );
        self::assertSame($recentToken, self::getConnection()->fetchOne(
            'SELECT access_token FROM ' . $table . ' WHERE access_token = ?',
            [$recentToken]
        ));
    }
}

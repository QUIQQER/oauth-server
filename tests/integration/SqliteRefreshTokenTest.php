<?php

namespace QUITest\QUI\OAuth\Integration;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception\LockWaitTimeoutException;
use Doctrine\DBAL\Schema\Table;
use OAuth2\Request;
use OAuth2\Response;
use OAuth2\ResponseType\AccessToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use QUI;
use QUI\OAuth\ClientConfiguration;
use QUI\OAuth\RotatingRefreshTokenGrant;
use QUI\OAuth\Setup;
use QUI\OAuth\Storage;
use ReflectionProperty;
use RuntimeException;

class SqliteRefreshTokenTest extends TestCase
{
    private Connection $First;
    private Connection $Second;
    private mixed $previousConnection;
    private ReflectionProperty $connectionProperty;
    private string $databaseFile;
    private string $refreshToken;

    protected function setUp(): void
    {
        $this->connectionProperty = new ReflectionProperty(QUI::class, 'QueryBuilder');
        $this->previousConnection = $this->connectionProperty->getValue();
        $file = tempnam(sys_get_temp_dir(), 'phpunit-oauth-sqlite-');
        self::assertIsString($file);
        $this->databaseFile = $file;
        $this->First = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $file]);
        $this->Second = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $file]);
        $this->First->executeStatement('PRAGMA busy_timeout = 0');
        $this->Second->executeStatement('PRAGMA busy_timeout = 0');
        $this->useConnection($this->First);

        $tables = [
            'oauth_clients' => ['client_id', 'allowed_resources'],
            'oauth_access_tokens' => ['access_token', 'client_id', 'user_id', 'expires', 'scope', 'resource'],
            'oauth_refresh_tokens' => [
                'refresh_token', 'client_id', 'user_id', 'expires', 'scope', 'resource',
                'token_family_id', 'replaced_by', 'replacement_access_token',
                'replacement_access_expires', 'replaced_at', 'revoked_at'
            ]
        ];

        foreach ($tables as $name => $columns) {
            $Table = new Table(Setup::getTable($name));

            foreach ($columns as $column) {
                $Table->addColumn($column, 'string', ['notnull' => $column === $columns[0]]);
            }

            $Table->setPrimaryKey([$columns[0]]);
            $this->First->createSchemaManager()->createTable($Table);
        }

        $this->First->insert(Setup::getTable('oauth_clients'), [
            'client_id' => 'sqlite-client',
            'allowed_resources' => ClientConfiguration::encodeResources(['https://example.test/mcp'])
        ]);
        $this->refreshToken = bin2hex(random_bytes(20));
        $this->storage($this->First)->setRefreshToken(
            $this->refreshToken,
            'sqlite-client',
            'sqlite-user',
            time() + 3600,
            null
        );
    }

    protected function tearDown(): void
    {
        foreach ([$this->First, $this->Second] as $Connection) {
            while ($Connection->isTransactionActive()) {
                $Connection->rollBack();
            }

            $Connection->close();
        }

        $this->connectionProperty->setValue(null, $this->previousConnection);

        foreach (['', '-wal', '-shm', '-journal'] as $suffix) {
            if (is_file($this->databaseFile . $suffix)) {
                unlink($this->databaseFile . $suffix);
            }
        }
    }

    public static function journalModes(): array
    {
        return [['DELETE'], ['WAL']];
    }

    public static function refreshModes(): array
    {
        return [['DELETE', false], ['WAL', false], ['DELETE', true], ['WAL', true]];
    }

    #[DataProvider('refreshModes')]
    public function testOverlappingRefreshRequestsAreSerialized(string $journalMode, bool $reusable): void
    {
        $this->setJournalMode($journalMode);

        if ($reusable) {
            $this->First->update(Setup::getTable('oauth_clients'), [
                'allowed_resources' => ClientConfiguration::encodeResources(['https://example.test/mcp'], true)
            ], ['client_id' => 'sqlite-client']);
        }

        $FirstStorage = $this->storage($this->First);
        $SecondStorage = $this->storage($this->Second);
        $FirstGrant = $this->validatedGrant($FirstStorage, $reusable);
        $SecondGrant = $this->validatedGrant($SecondStorage, $reusable);
        $this->useConnection($this->First);
        $this->First->beginTransaction();
        self::assertIsArray($FirstStorage->getRefreshTokenForUpdate($this->refreshToken));

        $this->useConnection($this->Second);

        try {
            $this->refresh($SecondGrant, $SecondStorage);
            self::fail('A concurrent refresh must not pass the writer lock.');
        } catch (LockWaitTimeoutException) {
            self::assertFalse($this->Second->isTransactionActive());
            self::assertSame(0, $this->countTokens('oauth_access_tokens'));
        }

        $this->useConnection($this->First);
        $first = $this->refresh($FirstGrant, $FirstStorage);
        $this->First->commit();
        $this->useConnection($this->Second);
        $second = $this->refresh($SecondGrant, $SecondStorage);
        self::assertNotEmpty($first['access_token']);
        self::assertNotEmpty($second['access_token']);

        if ($reusable) {
            self::assertArrayNotHasKey('refresh_token', $first);
            self::assertArrayNotHasKey('refresh_token', $second);
            self::assertNotSame($first['access_token'], $second['access_token']);
            self::assertSame(1, $this->countTokens('oauth_refresh_tokens'));
            self::assertSame(2, $this->countTokens('oauth_access_tokens'));
        } else {
            self::assertNotSame($this->refreshToken, $first['refresh_token']);
            self::assertSame($first['refresh_token'], $second['refresh_token']);
            self::assertSame($first['access_token'], $second['access_token']);
            self::assertSame(2, $this->countTokens('oauth_refresh_tokens'));
            self::assertSame(1, $this->countTokens('oauth_access_tokens'));
            $original = $SecondStorage->getRefreshToken($this->refreshToken);
            $replacement = $SecondStorage->getRefreshToken($first['refresh_token']);
            self::assertSame($original['token_family_id'], $replacement['token_family_id']);
        }
    }

    #[DataProvider('journalModes')]
    public function testRollbackReleasesLockAndRollsBackTokenIssuance(string $journalMode): void
    {
        $this->setJournalMode($journalMode);
        $Storage = $this->storage($this->First);
        $Grant = $this->validatedGrant($Storage);

        try {
            $this->First->transactional(function () use ($Grant, $Storage): void {
                $this->refresh($Grant, $Storage);
                throw new RuntimeException('Simulated failure after token issuance.');
            });
        } catch (RuntimeException $Exception) {
            self::assertSame('Simulated failure after token issuance.', $Exception->getMessage());
        }

        self::assertFalse($this->First->isTransactionActive());
        self::assertSame(0, $this->countTokens('oauth_access_tokens'));
        self::assertSame(1, $this->countTokens('oauth_refresh_tokens'));
        self::assertEmpty($Storage->getRefreshToken($this->refreshToken)['replaced_by']);
        $Storage = $this->storage($this->Second);
        $result = $this->refresh($this->validatedGrant($Storage), $Storage);
        self::assertNotEmpty($result['access_token']);
        self::assertNotSame($this->refreshToken, $result['refresh_token']);
    }

    public function testLockingRequiresAnActiveTransaction(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Locking a refresh token requires an active transaction.');
        $this->storage($this->First)->getRefreshTokenForUpdate($this->refreshToken);
    }

    public function testMissingTokenDoesNotChangeExistingTokens(): void
    {
        $Storage = $this->storage($this->First);
        $before = $Storage->getRefreshToken($this->refreshToken);
        $result = $this->First->transactional(
            static fn() => $Storage->getRefreshTokenForUpdate('missing-token')
        );
        self::assertFalse($result);
        self::assertSame($before, $Storage->getRefreshToken($this->refreshToken));
    }

    private function setJournalMode(string $mode): void
    {
        self::assertContains($mode, ['DELETE', 'WAL']);
        self::assertSame(strtolower($mode), $this->First->fetchOne('PRAGMA journal_mode = ' . $mode));
    }

    private function useConnection(Connection $Connection): void
    {
        $this->connectionProperty->setValue(null, $Connection);
    }

    private function storage(Connection $Connection): Storage
    {
        $this->useConnection($Connection);

        return new Storage($Connection->getNativeConnection());
    }

    private function validatedGrant(Storage $Storage, bool $reusable = false): RotatingRefreshTokenGrant
    {
        $Grant = new RotatingRefreshTokenGrant($Storage, 60, $reusable);
        self::assertTrue($Grant->validateRequest(
            new Request([], ['refresh_token' => $this->refreshToken]),
            new Response()
        ));

        return $Grant;
    }

    private function refresh(RotatingRefreshTokenGrant $Grant, Storage $Storage): array
    {
        return $Grant->createAccessToken(new AccessToken($Storage, $Storage), 'sqlite-client', 'sqlite-user', null);
    }

    private function countTokens(string $table): int
    {
        return (int)QUI::getDataBaseConnection()->fetchOne(
            'SELECT COUNT(*) FROM ' . QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable($table))
        );
    }
}

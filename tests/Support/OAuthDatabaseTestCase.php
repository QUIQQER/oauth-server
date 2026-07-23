<?php

namespace QUITest\QUI\OAuth\Support;

use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use QUI;
use QUI\Cache\LongTermCache;
use QUI\Interfaces\Users\User as UserInterface;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Setup;
use QUI\REST\Server as RestServer;
use QUI\Utils\Singleton;
use ReflectionProperty;
use Throwable;

abstract class OAuthDatabaseTestCase extends TestCase
{
    protected const TEST_PREFIX = 'phpunit-oauth-server-';

    private ?UserInterface $previousOAuthSessionUser = null;
    private array $previousGet = [];
    private array $previousPost = [];
    private array $previousRequest = [];
    private array $previousRequestBag = [];
    private array $previousServer = [];
    private array $previousLongTermCacheRuntime = [];
    private array $previousSingletonInstances = [];
    private mixed $previousRestServer = null;

    public static function setUpBeforeClass(): void
    {
        self::skipIfDatabaseIsUnavailable();
        self::cleanupFixtures();
    }

    protected function setUp(): void
    {
        parent::setUp();
        self::skipIfDatabaseIsUnavailable();
        self::cleanupFixtures();

        $this->previousGet = $_GET;
        $this->previousPost = $_POST;
        $this->previousRequest = $_REQUEST;
        $this->previousServer = $_SERVER;
        $this->previousRequestBag = QUI::getRequest()->request->all();
        $this->previousLongTermCacheRuntime = self::readStaticArray(LongTermCache::class, 'runtime');
        $this->previousSingletonInstances = self::readStaticArray(Singleton::class, 'instances');
        $this->previousRestServer = self::readStaticValue(RestServer::class, 'currentInstance');
        $this->previousOAuthSessionUser = self::replaceOAuthSessionUser(null);
    }

    protected function tearDown(): void
    {
        self::cleanupFixtures();
        self::replaceOAuthSessionUser($this->previousOAuthSessionUser);

        $_GET = $this->previousGet;
        $_POST = $this->previousPost;
        $_REQUEST = $this->previousRequest;
        $_SERVER = $this->previousServer;
        QUI::getRequest()->request->replace($this->previousRequestBag);
        self::writeStaticValue(LongTermCache::class, 'runtime', $this->previousLongTermCacheRuntime);
        self::writeStaticValue(Singleton::class, 'instances', $this->previousSingletonInstances);
        self::writeStaticValue(RestServer::class, 'currentInstance', $this->previousRestServer);

        parent::tearDown();
    }

    public static function tearDownAfterClass(): void
    {
        self::cleanupFixtures();
    }

    protected static function getConnection(): Connection
    {
        return QUI::getDataBaseConnection();
    }

    /**
     * @param array<string, array{active: bool, unlimitedCalls: bool, maxCalls?: int, maxCallsType?: string}> $scopes
     */
    protected static function createClient(array $scopes = [], bool $secretIsToken = false): string
    {
        return Handler::createOAuthClient(
            QUI::getUsers()->getSystemUser(),
            $scopes,
            self::TEST_PREFIX . bin2hex(random_bytes(6)),
            $secretIsToken
        );
    }

    /**
     * @return array<string, mixed>
     */
    protected static function fetchClient(string $clientId): array
    {
        $row = self::getConnection()->createQueryBuilder()
            ->select('*')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_clients')))
            ->where('client_id = :clientId')
            ->setParameter('clientId', $clientId)
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($row);

        return $row;
    }

    protected static function cacheName(string $secret): string
    {
        return 'quiqqer/oauth-server/client-data-with-secret-as-access-token/' . hash('sha256', $secret);
    }

    protected static function resetLongTermCacheRuntime(): void
    {
        $Property = new ReflectionProperty(LongTermCache::class, 'runtime');
        $Property->setValue(null, []);
    }

    private static function skipIfDatabaseIsUnavailable(): void
    {
        try {
            self::getConnection()->executeQuery(
                'SELECT 1 FROM '
                . QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_clients'))
                . ' LIMIT 1'
            )->free();
        } catch (Throwable $Exception) {
            self::markTestSkipped('QUIQQER OAuth database is not available: ' . $Exception->getMessage());
        }
    }

    private static function cleanupFixtures(): void
    {
        try {
            $Connection = self::getConnection();
            $clientTable = QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_clients'));
            $clients = $Connection->createQueryBuilder()
                ->select('client_id', 'client_secret')
                ->from($clientTable)
                ->where('name LIKE :name')
                ->setParameter('name', self::TEST_PREFIX . '%')
                ->executeQuery()
                ->fetchAllAssociative();

            foreach ($clients as $client) {
                $clientId = (string)$client['client_id'];
                $secret = (string)($client['client_secret'] ?? '');

                if ($secret !== '') {
                    LongTermCache::clear(self::cacheName($secret));
                }

                foreach (array_reverse(Setup::getClientTables()) as $table) {
                    $Connection->delete(
                        QUI\Utils\Doctrine::quoteIdentifier($table),
                        ['client_id' => $clientId]
                    );
                }
            }
        } catch (Throwable) {
            // The availability check reports database failures; cleanup must not hide test results.
        }
    }

    private static function replaceOAuthSessionUser(?UserInterface $User): ?UserInterface
    {
        $Property = new ReflectionProperty(Handler::class, 'SessionUser');
        $previous = $Property->getValue();
        $Property->setValue(null, $User);

        return $previous instanceof UserInterface ? $previous : null;
    }

    /**
     * @return array<mixed>
     */
    private static function readStaticArray(string $class, string $property): array
    {
        $value = self::readStaticValue($class, $property);

        return is_array($value) ? $value : [];
    }

    private static function readStaticValue(string $class, string $property): mixed
    {
        return (new ReflectionProperty($class, $property))->getValue();
    }

    private static function writeStaticValue(string $class, string $property, mixed $value): void
    {
        (new ReflectionProperty($class, $property))->setValue(null, $value);
    }
}

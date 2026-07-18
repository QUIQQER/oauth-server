<?php

namespace QUI\OAuth\Clients;

use DateTime;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Exception;
use Psr\Http\Message\ServerRequestInterface;
use QUI;
use QUI\Cache\LongTermCache;
use QUI\Interfaces\Users\User as QUIUserInterface;
use QUI\OAuth\Permission;
use QUI\Permissions\PermissionOrder;
use Ramsey\Uuid\Uuid;
use Throwable;

/**
 * Class Handler
 *
 * OAuth2 client handler
 */
class Handler
{
    /**
     * Runtime var for session user (based on oauth authentication).
     *
     * @var QUIUserInterface|null
     */
    protected static ?QUIUserInterface $SessionUser = null;

    /**
     * @deprecated - Will be removed in next major version. Use {@see Permission::MANAGE_CLIENTS} instead.
     */
    const PERMISSION_MANAGE_CLIENTS = 'quiqqer.oauth-server.manage_clients';

    /**
     * Creates oauth client credentials for the user
     *
     * @param QUIUserInterface $User
     * @param array<string, array<string, mixed>> $scopeSettings
     * @param string $name
     * @param bool $clientSecretIsPermanentAccessToken - If true, the client secret can be used as permanent access / Bearer token
     * @return string - New Client ID
     *
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     * @throws QUI\OAuth\Exception
     */
    public static function createOAuthClient(
        QUIUserInterface $User,
        array $scopeSettings,
        string $name = '',
        bool $clientSecretIsPermanentAccessToken = false
    ): string {
        if (QUI::getUsers()->isNobodyUser($User)) {
            throw new QUI\Exception('Could not create Client');
        }

        if (empty($name)) {
            $name = 'OAuth2 Client ' . date('Y-m-d');
        }

        try {
            $UUID = Uuid::uuid4();
            $clientId = $UUID->serialize();
        } catch (Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new QUI\OAuth\Exception([
                'quiqqer/oauth-server',
                'exception.could.not.create.client'
            ]);
        }

        $activeScopes = [];

        foreach ($scopeSettings as $scope => $settings) {
            if ($settings['active']) {
                $activeScopes[] = $scope;
            }
        }

        $Connection = QUI::getDataBaseConnection();
        $Connection->insert(
            QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')),
            [
                'client_id' => $clientId,
                'client_secret' => self::generatePassword(),
                'user_id' => $User->getId(),
                'name' => $name,
                'c_date' => time(),
                'scope' => empty($activeScopes) ? null : implode(' ', $activeScopes),
                'scope_restrictions' => json_encode($scopeSettings),
                'client_secret_is_token' => $clientSecretIsPermanentAccessToken ? 1 : 0
            ]
        );

        // Insert default access limit data for all active scopes
        foreach ($activeScopes as $scope) {
            $Connection->insert(
                QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_access_limits')),
                [
                    'client_id' => $clientId,
                    'scope' => $scope
                ]
            );
        }

        return $clientId;
    }

    /**
     * Generate a random password
     *
     * @param int $len (optional) - Password length [default: 40]
     * @return string
     * @throws Exception
     */
    public static function generatePassword(int $len = 40): string
    {
        $characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()[]{}?!%&/=*+~,.;:-_";
        $max = mb_strlen($characters) - 1;
        $passwordCharacters = [];

        for ($i = 0; $i < $len; $i++) {
            $passwordCharacters[] = $characters[random_int(0, $max)];
        }

        return implode('', $passwordCharacters);
    }

    /**
     * Return all oauth clients from the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @return list<array<string, mixed>>
     *
     * @throws QUI\Exception
     */
    public static function getOAuthClientsByUser(QUI\Interfaces\Users\User $User): array
    {
        $QueryBuilder = QUI::getQueryBuilder();

        return $QueryBuilder
            ->select('*')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')))
            ->where($QueryBuilder->expr()->eq('user_id', ':userId'))
            ->setParameter('userId', $User->getId())
            ->executeQuery()
            ->fetchAllAssociative();
    }

    /**
     * Return a client from the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param string $clientId
     * @return list<array<string, mixed>>
     *
     * @throws QUI\Exception
     */
    public static function getOAuthClientByUser(QUI\Interfaces\Users\User $User, string $clientId): array
    {
        $QueryBuilder = QUI::getQueryBuilder();

        return $QueryBuilder
            ->select('*')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')))
            ->where($QueryBuilder->expr()->eq('user_id', ':userId'))
            ->andWhere($QueryBuilder->expr()->eq('client_id', ':clientId'))
            ->setParameter('userId', $User->getId())
            ->setParameter('clientId', $clientId)
            ->executeQuery()
            ->fetchAllAssociative();
    }

    /**
     * Return a client by access token
     *
     * @param string $accessToken
     * @param bool $includeClientWithClientSecretAsPermanentAccessToken
     * This also fetches clients that have set the client secret as permanent access token
     *
     * @return array<string, mixed>|false
     *
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     */
    public static function getOAuthClientByAccessToken(
        string $accessToken,
        bool $includeClientWithClientSecretAsPermanentAccessToken = false
    ): bool | array {
        $QueryBuilder = QUI::getQueryBuilder();
        $result = $QueryBuilder
            ->select('client_id')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_access_tokens')))
            ->where($QueryBuilder->expr()->eq('access_token', ':accessToken'))
            ->setParameter('accessToken', $accessToken)
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($result !== false) {
            return self::getOAuthClient((string)$result['client_id']);
        }

        if ($includeClientWithClientSecretAsPermanentAccessToken === false) {
            return false;
        }

        $QueryBuilder = QUI::getQueryBuilder();
        $result = $QueryBuilder
            ->select('client_id', 'client_secret')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')))
            ->where($QueryBuilder->expr()->eq('client_secret', ':accessToken'))
            ->andWhere($QueryBuilder->expr()->eq('client_secret_is_token', ':secretIsToken'))
            ->setParameter('accessToken', $accessToken)
            ->setParameter('secretIsToken', 1)
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($result === false || !hash_equals((string)$result['client_secret'], $accessToken)) {
            return false;
        }

        return self::getOAuthClient((string)$result['client_id']);
    }

    /**
     * Update the data from a client
     * You can update the following data:
     *
     * - name
     * - scope_restrictions
     *
     * @param string $clientId
     * @param array<string, mixed> $data
     *
     * @throws QUI\OAuth\Exception
     * @throws QUI\Exception
     */
    public static function updateOAuthClient(string $clientId, array $data = []): void
    {
        $update = [];

        if (!empty($data['title']) && is_string($data['title'])) {
            $update['name'] = $data['title'];
        }

        $activeScopes = [];

        if (!empty($data['scope_restrictions']) && is_array($data['scope_restrictions'])) {
            $availableScopes = QUI\REST\Server::getInstance()->getEntryPoints();

            foreach ($data['scope_restrictions'] as $scope => $settings) {
                if (!in_array($scope, $availableScopes)) {
                    unset($data['scope_restrictions'][$scope]);
                    continue;
                }

                if ($settings['active']) {
                    $activeScopes[] = $scope;
                }
            }

            $update['scope_restrictions'] = json_encode($data['scope_restrictions']);
            $update['scope'] = empty($activeScopes) ? null : implode(' ', $activeScopes);
        }

        if (!empty($data['clientSecret'])) {
            $update['client_secret'] = $data['clientSecret'];
        }

        $clientSecretIsToken = !empty($data['clientSecretIsToken']);
        $update['client_secret_is_token'] = $clientSecretIsToken ? 1 : 0;

        $tableClients = QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients'));
        $previousClientData = self::getOAuthClient($clientId);

        QUI::getDataBaseConnection()->update(
            $tableClients,
            $update,
            [
                'client_id' => $clientId
            ]
        );

        // If client secret is not a permanent access token (anymore), we have to delete it from cache
        if (
            !empty($previousClientData['client_secret_is_token'])
            && (
                $clientSecretIsToken === false
                || (
                    isset($update['client_secret'])
                    && !hash_equals((string)$previousClientData['client_secret'], (string)$update['client_secret'])
                )
            )
        ) {
            self::clearCacheForClientSecretAsAccessToken((string)$previousClientData['client_secret']);
        }

        // Write limit data for all active scopes to database
        $Connection = QUI::getDataBaseConnection();
        $table = QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_access_limits'));

        foreach ($activeScopes as $scope) {
            $QueryBuilder = QUI::getQueryBuilder();
            $exists = $QueryBuilder
                ->select('1')
                ->from($table)
                ->where($QueryBuilder->expr()->eq('client_id', ':clientId'))
                ->andWhere($QueryBuilder->expr()->eq('scope', ':scope'))
                ->setParameter('clientId', $clientId)
                ->setParameter('scope', $scope)
                ->setMaxResults(1)
                ->executeQuery()
                ->fetchOne();

            if ($exists !== false) {
                continue;
            }

            try {
                $Connection->insert($table, [
                    'client_id' => $clientId,
                    'scope' => $scope
                ]);
            } catch (UniqueConstraintViolationException) {
                // Another request created the same client/scope metadata concurrently.
            }
        }
    }

    /**
     * Return oauth client data
     *
     * @param string $clientId
     * @return array<string, mixed>
     *
     * @throws QUI\Exception
     */
    public static function getOAuthClient(string $clientId): array
    {
        $QueryBuilder = QUI::getQueryBuilder();
        $result = $QueryBuilder
            ->select('*')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')))
            ->where($QueryBuilder->expr()->eq('client_id', ':clientId'))
            ->setParameter('clientId', $clientId)
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($result === false) {
            throw new QUI\OAuth\Exception(
                [
                    'quiqqer/oauth-server',
                    'exception.client.not.found'
                ],
                404
            );
        }

        return $result;
    }

    /**
     * Delete an oauth client
     *
     * @param string $clientId
     * @throws QUI\Exception
     */
    public static function removeOAuthClient(string $clientId): void
    {
        self::clearCacheForClientSecretAsAccessTokenByClientId($clientId);
        $Connection = QUI::getDataBaseConnection();

        foreach (QUI\OAuth\Setup::getClientTables() as $table) {
            $Connection->delete(
                QUI\Utils\Doctrine::quoteIdentifier($table),
                ['client_id' => $clientId]
            );
        }
    }

    /**
     * Get current access limit information for an OAuth client
     *
     * @param string $clientId
     * @param string|null $scope (optional) - Restrict results to a specific scope
     * @return array<string, array<string, mixed>>
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     */
    public static function getClientLimits(string $clientId, ?string $scope = null): array
    {
        $clientData = self::getOAuthClient($clientId);
        $scopRestrictions = json_decode($clientData['scope_restrictions'], true);

        $limits = [];
        $QueryBuilder = QUI::getQueryBuilder();
        $QueryBuilder
            ->select('scope', 'total_usage_count', 'interval_usage_count', 'first_usage', 'last_usage')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_access_limits')))
            ->where($QueryBuilder->expr()->eq('client_id', ':clientId'))
            ->setParameter('clientId', $clientId);

        if ($scope !== null) {
            $QueryBuilder
                ->andWhere($QueryBuilder->expr()->eq('scope', ':scope'))
                ->setParameter('scope', $scope);
        }

        $result = $QueryBuilder->executeQuery()->fetchAllAssociative();

        foreach ($result as $row) {
            $scope = $row['scope'];
            unset($row['scope']);

            $row['queryLimitReached'] = false;

            if (isset($scopRestrictions[$scope])) {
                if ($scopRestrictions[$scope]['maxCallsType'] !== 'absolute') {
                    $row['queryLimitReached'] = (int)$row['interval_usage_count'] >= (int)$scopRestrictions[$scope]['maxCalls'];
                }
            }

            $limits[$scope] = $row;
        }

        return $limits;
    }

    /**
     * Reset access limits for an OAuth client
     *
     * @param string $clientId
     * @param string|null $scope (optional) - Restrict reset to a specific scope
     * @return void
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     * @throws QUI\OAuth\Exception
     */
    public static function resetClientLimits(string $clientId, ?string $scope = null): void
    {
        $table = QUI\OAuth\Setup::getTable('oauth_access_limits');

        // Check if DB entry for scope exists
        if (!is_null($scope)) {
            $QueryBuilder = QUI::getQueryBuilder();
            $result = $QueryBuilder
                ->select('1')
                ->from(QUI\Utils\Doctrine::quoteIdentifier($table))
                ->where($QueryBuilder->expr()->eq('client_id', ':clientId'))
                ->andWhere($QueryBuilder->expr()->eq('scope', ':scope'))
                ->setParameter('clientId', $clientId)
                ->setParameter('scope', $scope)
                ->setMaxResults(1)
                ->executeQuery()
                ->fetchOne();

            if ($result === false) {
                throw new QUI\OAuth\Exception(
                    QUI::getLocale()->get(
                        'quiqqer/oauth-server',
                        'exception.Handler.resetClientLimits.scope_not_found'
                    )
                );
            }
        }

        $where = [
            'client_id' => $clientId
        ];

        if (!is_null($scope)) {
            $where['scope'] = $scope;
        }

        QUI::getDataBaseConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier($table),
            [
                'interval_usage_count' => 0,
                'first_usage' => 0,
                'last_usage' => 0
            ],
            $where
        );
    }

    /**
     * Deletes expired OAuth credentials after a 24-hour diagnostics window.
     *
     * @return void
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     */
    public static function cleanupAccessTokens(): void
    {
        $MinAge = new DateTime('-24 hours');

        foreach (['oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_authorization_codes'] as $table) {
            $QueryBuilder = QUI::getQueryBuilder();
            $QueryBuilder
                ->delete(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable($table)))
                ->where($QueryBuilder->expr()->lte('expires', ':minimumExpiration'))
                ->setParameter('minimumExpiration', $MinAge->format('Y-m-d H:i:s'))
                ->executeStatement();
        }
    }

    /**
     * Get QUIQQER user that is currently authenticated via OAuth.
     *
     * @return QUIUserInterface
     */
    public static function getSessionUser(): QUIUserInterface
    {
        if (empty(self::$SessionUser)) {
            return QUI::getUserBySession();
        }

        return self::$SessionUser;
    }

    /**
     * Set QUIQQER user that is currently authenticated via OAuth.
     *
     * @param QUIUserInterface $SessionUser
     * @return void
     */
    public static function setSessionUser(QUIUserInterface $SessionUser): void
    {
        self::$SessionUser = $SessionUser;
    }

    /**
     * Checks if a request contains an access token that is a client secret that is enabled
     * as a permanent access token.
     *
     * @param ServerRequestInterface $request
     * @return array<string, mixed>|null - OAuth Client data or null if no such client exists
     */
    public static function getOAuthClientDataByRequestWithClientSecretAsToken(ServerRequestInterface $request): ?array
    {
        $authHeader = $request->getHeaderLine('Authorization');
        $token = null;

        if (stripos($authHeader, 'Bearer ') === 0) {
            $token = trim(substr($authHeader, 7));
        }

        $queryParams = $request->getQueryParams();

        if (empty($token) && !empty($queryParams['access_token'])) {
            $token = $queryParams['access_token'];
        }

        if (empty($token)) {
            return null;
        }

        $cacheName = self::getCacheNameForClientSecretsAsAccessTokens($token);

        try {
            return LongTermCache::get($cacheName);
        } catch (QUI\Cache\Exception) {
            // re-build cache
        } catch (Throwable $e) {
            QUI\System\Log::writeException($e);
        }

        try {
            $QueryBuilder = QUI::getQueryBuilder();
            $result = $QueryBuilder
                ->select('*')
                ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')))
                ->where($QueryBuilder->expr()->eq('client_secret', ':token'))
                ->andWhere($QueryBuilder->expr()->eq('client_secret_is_token', ':secretIsToken'))
                ->setParameter('token', $token)
                ->setParameter('secretIsToken', 1)
                ->setMaxResults(1)
                ->executeQuery()
                ->fetchAssociative();

            if ($result === false || !hash_equals((string)$result['client_secret'], $token)) {
                return null;
            }

            LongTermCache::set($cacheName, $result);

            return $result;
        } catch (\Exception $exception) {
            QUI\System\Log::writeException($exception);
            return null;
        }
    }

    /**
     * @param QUIUserInterface $user
     * @return int|null - null if no limit is set
     */
    public static function getMaxNumberOfPermanentAccessTokens(QUIUserInterface $user): ?int
    {
        try {
            $maxNumberOfOauthClientsWithPermanentAccessToken = PermissionOrder::maxInteger(
                Permission::MAX_NUMBER_OF_PERMANENT_ACCESS_TOKENS->value,
                [$user]
            );
        } catch (\Exception $exception) {
            QUI\System\Log::writeException($exception);
            return 0;
        }

        if ($maxNumberOfOauthClientsWithPermanentAccessToken === -1) {
            return null;
        }

        return $maxNumberOfOauthClientsWithPermanentAccessToken;
    }

    /**
     * @param QUIUserInterface $user
     * @return int
     * @throws QUI\Exception
     */
    public static function getNumberOfPermanentAccessTokens(QUIUserInterface $user): int
    {
        return count(self::getOAuthClientsWithPermanentAccessToken($user));
    }

    /**
     * @param QUIUserInterface $user
     * @return list<array<string, mixed>> - empty list if no clients exist
     * @throws QUI\Exception
     */
    public static function getOAuthClientsWithPermanentAccessToken(QUIUserInterface $user): array
    {
        $oauthClients = self::getOAuthClientsByUser($user);
        $oauthClientsWithPermanentAccessToken = [];

        foreach ($oauthClients as $oauthClientData) {
            if (!empty($oauthClientData['client_secret_is_token'])) {
                $oauthClientsWithPermanentAccessToken[] = $oauthClientData;
            }
        }

        return $oauthClientsWithPermanentAccessToken;
    }

    private static function getCacheNameForClientSecretsAsAccessTokens(string $token): string
    {
        return 'quiqqer/oauth-server/client-data-with-secret-as-access-token/' . hash('sha256', $token);
    }

    /**
     * @param string $clientId
     * @return void
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     */
    private static function clearCacheForClientSecretAsAccessTokenByClientId(string $clientId): void
    {
        $QueryBuilder = QUI::getQueryBuilder();
        $result = $QueryBuilder
            ->select('client_secret')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(QUI\OAuth\Setup::getTable('oauth_clients')))
            ->where($QueryBuilder->expr()->eq('client_id', ':clientId'))
            ->setParameter('clientId', $clientId)
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($result !== false && !empty($result['client_secret'])) {
            self::clearCacheForClientSecretAsAccessToken((string)$result['client_secret']);
        }
    }

    private static function clearCacheForClientSecretAsAccessToken(string $secret): void
    {
        LongTermCache::clear(self::getCacheNameForClientSecretsAsAccessTokens($secret));
    }
}

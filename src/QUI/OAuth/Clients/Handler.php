<?php

namespace QUI\OAuth\Clients;

use DateTime;
use Exception;
use PDOException;
use QUI;
use Ramsey\Uuid\Uuid;
use QUI\Interfaces\Users\User as QUIUserInterface;

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

    const PERMISSION_MANAGE_CLIENTS = 'quiqqer.oauth-server.manage_clients';

    /**
     * Creates oauth client credentials for the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param string $name
     * @param array $scopeSettings
     * @return string - New Client ID
     *
     * @throws QUI\Permissions\Exception
     * @throws QUI\Exception
     * @throws Exception
     */
    public static function createOAuthClient(
        QUI\Interfaces\Users\User $User,
        array $scopeSettings,
        string $name = ''
    ): string {
        self::checkManagePermission();

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

        QUI::getDataBase()->insert(
            QUI\OAuth\Setup::getTable('oauth_clients'),
            [
                'client_id' => $clientId,
                'client_secret' => self::generatePassword(),
                'user_id' => $User->getId(),
                'name' => $name,
                'c_date' => time(),
                'scope' => empty($activeScopes) ? null : implode(' ', $activeScopes),
                'scope_restrictions' => json_encode($scopeSettings)
            ]
        );

        // Insert default access limit data for all active scopes
        foreach ($activeScopes as $scope) {
            QUI::getDataBase()->insert(
                QUI\OAuth\Setup::getTable('oauth_access_limits'),
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
    protected static function generatePassword(int $len = 40): string
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
     * @return array
     *
     * @throws QUI\Permissions\Exception
     * @throws QUI\Exception
     */
    public static function getOAuthClientsByUser(QUI\Interfaces\Users\User $User): array
    {
        self::checkManagePermission();

        return QUI::getDataBase()->fetch([
            'from' => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => [
                'user_id' => $User->getId()
            ]
        ]);
    }

    /**
     * Return a client from the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param string $clientId
     * @return array
     *
     * @throws QUI\Permissions\Exception
     * @throws QUI\Exception
     */
    public static function getOAuthClientByUser(QUI\Interfaces\Users\User $User, string $clientId): array
    {
        self::checkManagePermission();

        return QUI::getDataBase()->fetch([
            'from' => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => [
                'user_id' => $User->getId(),
                'client_id' => $clientId
            ]
        ]);
    }

    /**
     * Return a client by access token
     *
     * @param string $accessToken
     * @return array|false
     *
     * @throws QUI\Exception
     */
    public static function getOAuthClientByAccessToken(string $accessToken): bool|array
    {
        $result = QUI::getDataBase()->fetch([
            'select' => ['client_id'],
            'from' => QUI\OAuth\Setup::getTable('oauth_access_tokens'),
            'where' => [
                'access_token' => $accessToken
            ]
        ]);

        if (empty($result)) {
            return false;
        }

        return self::getOAuthClient($result[0]['client_id']);
    }

    /**
     * Update the data from a client
     * You can update the following data:
     *
     * - name
     * - scope_restrictions
     *
     * @param string $clientId
     * @param array $data
     *
     * @throws QUI\OAuth\Exception
     * @throws QUI\Permissions\Exception
     * @throws QUI\Exception
     */
    public static function updateOAuthClient(string $clientId, array $data = []): void
    {
        self::checkManagePermission();

        if (!is_array($data)) {
            throw new QUI\OAuth\Exception(
                [
                    'quiqqer/oauth-server',
                    'exception.client.could.not.save'
                ],
                404
            );
        }

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

        QUI::getDataBase()->update(
            QUI\OAuth\Setup::getTable('oauth_clients'),
            $update,
            [
                'client_id' => $clientId
            ]
        );

        // Write limit data for all active scopes to database
        $PDO = QUI::getDataBase()->getPDO();
        $table = QUI\OAuth\Setup::getTable('oauth_access_limits');

        foreach ($activeScopes as $scope) {
            try {
                $Statement = $PDO->prepare(
                    'INSERT INTO `' . $table . '` (`client_id`, `scope`)'
                    . ' SELECT ' . $PDO->quote($clientId) . ', ' . $PDO->quote($scope)
                    . ' FROM DUAL'
                    . ' WHERE NOT EXISTS ('
                    . '   SELECT 1 FROM `' . $table . '`'
                    . '   WHERE `client_id` =' . $PDO->quote($clientId)
                    . '   AND `scope` =' . $PDO->quote($scope)
                    . ')'
                    . ' LIMIT 1'
                );

                $Statement->execute();
            } catch (PDOException $Exception) {
                QUI\System\Log::writeException($Exception);
            }
        }
    }

    /**
     * Return oauth client data
     *
     * @param string $clientId
     * @return array
     *
     * @throws QUI\Permissions\Exception
     * @throws QUI\Exception
     */
    public static function getOAuthClient(string $clientId): array
    {
        self::checkManagePermission();

        $result = QUI::getDataBase()->fetch([
            'from' => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => [
                'client_id' => $clientId
            ]
        ]);

        if (!isset($result[0])) {
            throw new QUI\OAuth\Exception(
                [
                    'quiqqer/oauth-server',
                    'exception.client.not.found'
                ],
                404
            );
        }

        return $result[0];
    }

    /**
     * Delete an oauth client
     *
     * @param string $clientId
     *
     * @throws QUI\Permissions\Exception
     * @throws QUI\Exception
     */
    public static function removeOAuthClient(string $clientId): void
    {
        self::checkManagePermission();

        $DB = QUI::getDataBase();

        foreach (QUI\OAuth\Setup::getClientTables() as $table) {
            $DB->delete($table, ['client_id' => $clientId]);
        }
    }

    /**
     * Get current access limit information for an OAuth client
     *
     * @param string $clientId
     * @param string|null $scope (optional) - Restrict results to a specific scope
     * @return array
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     * @throws QUI\Permissions\Exception
     */
    public static function getClientLimits(string $clientId, string $scope = null): array
    {
        self::checkManagePermission();

        $clientData = self::getOAuthClient($clientId);
        $scopRestrictions = json_decode($clientData['scope_restrictions'], true);

        $limits = [];
        $where = [
            'client_id' => $clientId
        ];

        if (!is_null($scope)) {
            $where['scope'] = $scope;
        }

        $result = QUI::getDataBase()->fetch([
            'select' => ['scope', 'total_usage_count', 'interval_usage_count', 'first_usage', 'last_usage'],
            'from' => QUI::getDBTableName('oauth_access_limits'),
            'where' => $where
        ]);

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
     * @throws QUI\Permissions\Exception
     */
    public static function resetClientLimits(string $clientId, string $scope = null): void
    {
        self::checkManagePermission();

        $table = QUI\OAuth\Setup::getTable('oauth_access_limits');

        // Check if DB entry for scope exists
        if (!is_null($scope)) {
            $result = QUI::getDataBase()->fetch([
                'select' => 1,
                'from' => $table,
                'where' => [
                    'client_id' => $clientId,
                    'scope' => $scope
                ]
            ]);

            if (empty($result)) {
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

        QUI::getDataBase()->update($table, [
            'interval_usage_count' => 0,
            'first_usage' => 0,
            'last_usage' => 0
        ], $where);
    }

    /**
     * Checks if the current user is allowed to manage OAuth clients
     *
     * @return void
     * @throws QUI\Permissions\Exception
     */
    protected static function checkManagePermission(): void
    {
        // Client data must be at least readable if a REST request has to be authenticated
        if (defined('OAUTH_REST_REQUEST') && OAUTH_REST_REQUEST) {
            return;
        }

        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);
    }

    /**
     * Deletes all access tokens that are expired for at least 24 hours
     *
     * @return void
     * @throws QUI\Database\Exception
     * @throws QUI\Exception
     */
    public static function cleanupAccessTokens(): void
    {
        $MinAge = new DateTime('-24 hours');

        QUI::getDataBase()->delete(
            QUI\OAuth\Setup::getTable('oauth_access_tokens'),
            [
                'expires' => [
                    'type' => '<=',
                    'value' => $MinAge->format('Y-m-d H:i:s')
                ]
            ]
        );
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
}

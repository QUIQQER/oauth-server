<?php

/**
 * This file contains QUI\OAuth\Clients\Handler
 */

namespace QUI\OAuth\Clients;

use QUI;
use Ramsey\Uuid\Uuid;

/**
 * Class Handler
 *
 * OAuth2 client handler
 */
class Handler
{
    const PERMISSION_MANAGE_CLIENTS = 'quiqqer.oauth-server.manage_clients';

    /**
     * Creates oauth client credentials for the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param string $name
     * @param array $scopeSettings
     * @return string - New Client ID
     *
     * @throws \QUI\Permissions\Exception
     * @throws \QUI\Exception
     * @throws \Exception
     */
    public static function createOAuthClient(QUI\Interfaces\Users\User $User, $scopeSettings, $name = '')
    {
        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);

        if (QUI::getUsers()->isNobodyUser($User)) {
            throw new QUI\Exception('Could not create Client');
        }

        if (empty($name)) {
            $name = 'OAuth2 Client '.date('Y-m-d');
        }

        try {
            $UUID     = Uuid::uuid4();
            $clientId = $UUID->serialize();
        } catch (\Exception $Exception) {
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
                'client_id'          => $clientId,
                'client_secret'      => self::generatePassword(),
                'user_id'            => $User->getId(),
                'name'               => $name,
                'c_date'             => time(),
                'scope'              => empty($activeScopes) ? null : implode(' ', $activeScopes),
                'scope_restrictions' => json_encode($scopeSettings)
            ]
        );

        return $clientId;
    }

    /**
     * Generate a random password
     *
     * @param int $len (optional) - Password length [default: 40]
     * @return string
     * @throws \Exception
     */
    protected static function generatePassword($len = 40)
    {
        $characters         = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()[]{}?!$%&/=*+~,.;:<>-_";
        $max                = mb_strlen($characters) - 1;
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
     * @throws \QUI\Permissions\Exception
     * @throws \QUI\Exception
     */
    public static function getOAuthClientsByUser(QUI\Interfaces\Users\User $User)
    {
        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);

        return QUI::getDataBase()->fetch([
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => [
                'user_id' => $User->getId()
            ]
        ]);
    }

    /**
     * Return a client from the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param int $clientId
     * @return array
     *
     * @throws \QUI\Permissions\Exception
     * @throws \QUI\Exception
     */
    public static function getOAuthClientByUser(QUI\Interfaces\Users\User $User, $clientId)
    {
        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);

        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if (!isset($result[0])) {
            throw new QUI\OAuth\Exception(
                [
                    'quiqqer/oauth-server',
                    'exception.client.not.found'
                ],
                404
            );
        }

        return QUI::getDataBase()->fetch([
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => [
                'user_id'   => $User->getId(),
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
     * @throws \QUI\Exception
     */
    public static function getOAuthClientByAccessToken($accessToken)
    {
        $result = QUI::getDataBase()->fetch([
            'select' => ['client_id'],
            'from'   => QUI\OAuth\Setup::getTable('oauth_access_tokens'),
            'where'  => [
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
     * @param int $clientId
     * @param array $data
     *
     * @throws \QUI\OAuth\Exception
     * @throws \QUI\Permissions\Exception
     * @throws \QUI\Exception
     */
    public static function updateOAuthClient($clientId, $data = [])
    {
        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);

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

        if (!empty($data['scope_restrictions']) && is_array($data['scope_restrictions'])) {
            $availableScopes = QUI\REST\Server::getInstance()->getEntryPoints();

            foreach ($data['scope_restrictions'] as $scope => $settings) {
                if (!in_array($scope, $availableScopes)) {
                    unset($data['scope_restrictions'][$scope]);
                }
            }

            $update['scope_restrictions'] = json_encode($data['scope_restrictions']);
        }

        QUI::getDataBase()->update(
            QUI\OAuth\Setup::getTable('oauth_clients'),
            $update,
            [
                'client_id' => $clientId
            ]
        );
    }

    /**
     * Return oauth client data
     *
     * @param int $clientId
     * @return array
     *
     * @throws \QUI\Permissions\Exception
     * @throws \QUI\Exception
     */
    public static function getOAuthClient($clientId)
    {
        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);

        $result = QUI::getDataBase()->fetch([
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
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
     * Delete a oauth client
     *
     * @param int $clientId
     *
     * @throws \QUI\Permissions\Exception
     * @throws \QUI\Exception
     */
    public static function removeOAuthClient($clientId)
    {
        QUI\Permissions\Permission::checkPermission(self::PERMISSION_MANAGE_CLIENTS);

        QUI::getDataBase()->delete(QUI\OAuth\Setup::getTable('oauth_clients'), [
            'client_id' => $clientId
        ]);

        // @todo Token löschen und alles andere, was mit der client_ID zusammenhängt
    }
}

<?php

/**
 * This file contains QUI\OAuth\Clients\Handler
 */
namespace QUI\OAuth\Clients;

use QUI;
use QUI\Utils\Security\Orthos;

/**
 * Class Handler
 * @package QUI\OAuth\Clients
 */
class Handler
{
    /**
     * Creates oauth client credentials for the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param string $name
     * @return string
     *
     * @throws QUI\Exception
     */
    public static function createOAuthClient(QUI\Interfaces\Users\User $User, $name = '')
    {
        if (QUI::getUsers()->isNobodyUser($User)) {
            throw new QUI\Exception('Could not create Client');
        }

        $table = QUI\OAuth\Setup::getTable('oauth_clients');

        if (empty($name)) {
            $name = 'OAuth Client ' . date('Y-m-d H:i:s');
        }

        QUI::getDataBase()->insert($table, array(
            'client_id'     => Orthos::getPassword(80),
            'client_secret' => Orthos::getPassword(80),
            'user_id'       => $User->getId(),
            'name'          => $name
        ));

        return QUI::getDataBase()->getPDO()->lastInsertId('client_id');
    }

    /**
     * Return all oauth clients from the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @return array
     */
    public static function getOAuthClientsByUser(QUI\Interfaces\Users\User $User)
    {
        return QUI::getDataBase()->fetch(array(
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => array(
                'user_id' => $User->getId()
            )
        ));
    }

    /**
     * Return a client from the user
     *
     * @param QUI\Interfaces\Users\User $User
     * @param $clientId
     * @return array
     */
    public static function getOAuthClientByUser(QUI\Interfaces\Users\User $User, $clientId)
    {
        return QUI::getDataBase()->fetch(array(
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => array(
                'user_id'   => $User->getId(),
                'client_id' => $clientId
            )
        ));
    }


    public static function updateOAuthClient($clientId, $data, $User = null)
    {
        self::checkPermissions('permission.delete.update', $User);
    }

    /**
     * Delete a oauth client
     *
     * @param $clientId
     * @param null $User
     */
    public static function deleteOAuthClient($clientId, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        self::checkPermissions('permission.delete.oauth', $User);


        QUI::getDataBase()->delete(QUI\OAuth\Setup::getTable('oauth_clients'), array(
            'client_id' => $clientId
        ));
    }

    /**
     * @param string $permission
     * @param null $User
     * @throw QUI\Permissions\Exception
     */
    protected static function checkPermissions($permission, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        if ($User->isSU()) {
            return;
        }

        if (QUI::getUsers()->isSystemUser($User)) {
            return;
        }

        QUI\Permissions\Permission::checkPermission($permission);
    }
}

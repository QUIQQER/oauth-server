<?php

/**
 * This file contains QUI\OAuth\Clients\Handler
 */
namespace QUI\OAuth\Clients;

use QUI;
use QUI\Utils\Security\Orthos;

use Rhumsaa\Uuid\Uuid;
use Rhumsaa\Uuid\Exception\UnsatisfiedDependencyException;

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
            $name = 'OAuth Client ' . date('Y-m-d');
        }


        try {
            $UUID     = Uuid::uuid1();
            $clientId = $UUID->toString();
        } catch (UnsatisfiedDependencyException $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new QUI\OAuth\Exception(array(
                'quiqqer/oauth-server',
                'exception.could.not.create.client'
            ));
        }

        QUI::getDataBase()->insert($table, array(
            'client_id'     => $clientId,
            'client_secret' => Orthos::getPassword(rand(20, 80)),
            'user_id'       => $User->getId(),
            'name'          => $name,
            'c_date'        => time()
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
        self::isAllowed(false, $User);

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
     *
     * @throws QUI\OAuth\Exception|QUI\Permissions\Exception
     */
    public static function getOAuthClientByUser(QUI\Interfaces\Users\User $User, $clientId)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        self::isAllowed($clientId, $User);

        if (!isset($result[0])) {
            throw new QUI\OAuth\Exception(
                array(
                    'quiqqer/oauth-server',
                    'exception.client.not.found'
                ),
                404
            );
        }

        return QUI::getDataBase()->fetch(array(
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => array(
                'user_id'   => $User->getId(),
                'client_id' => $clientId
            )
        ));
    }

    /**
     * Update the data from a client
     * You can update the following data:
     *
     * - name
     *
     * @param $clientId
     * @param array $data
     * @param null $User
     *
     * @throws QUI\OAuth\Exception
     */
    public static function updateOAuthClient($clientId, $data = array(), $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        self::checkPermissions('permission.oauth.client.update', $User);
        self::isAllowed($clientId, $User);

        if (!is_array($data)) {
            throw new QUI\OAuth\Exception(
                array(
                    'quiqqer/oauth-server',
                    'exception.client.could.not.save'
                ),
                404
            );
        }

        if (!isset($data['name'])) {
            return;
        }

        QUI::getDataBase()->update(
            QUI\OAuth\Setup::getTable('oauth_clients'),
            array(
                'name' => $data['name']
            ),
            array(
                'user_id'   => $User->getId(),
                'client_id' => $clientId
            )
        );
    }

    /**
     * Return oauth client data
     *
     * @param $clientId
     * @param null $User
     * @return array
     *
     * @throws QUI\OAuth\Exception|QUI\Permissions\Exception
     */
    public static function getOAuthClient($clientId, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        self::isAllowed($clientId, $User);

        $result = QUI::getDataBase()->fetch(array(
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => array(
                'client_id' => $clientId
            )
        ));

        if (!isset($result[0])) {
            throw new QUI\OAuth\Exception(
                array(
                    'quiqqer/oauth-server',
                    'exception.client.not.found'
                ),
                404
            );
        }

        return $result[0];
    }

    /**
     * Delete a oauth client
     *
     * @param $clientId
     * @param null $User
     */
    public static function removeOAuthClient($clientId, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        self::checkPermissions('permission.oauth.client.delete', $User);
        self::isAllowed($clientId, $User);

        QUI::getDataBase()->delete(QUI\OAuth\Setup::getTable('oauth_clients'), array(
            'client_id' => $clientId
        ));
    }

    /**
     * @param string $permission
     * @param null|QUI\Interfaces\Users\User $User
     *
     * @throw QUI\Permissions\Exception
     */
    protected static function checkPermissions($permission, $User = null)
    {
        self::isAllowed($User);

        QUI\Permissions\Permission::checkPermission($permission);
    }

    /**
     * Checks if the user is allowed to do some action
     *
     * @param bool|string $clientId
     * @param null|QUI\Interfaces\Users\User $User
     *
     * @throws QUI\Permissions\Exception
     */
    protected static function isAllowed($clientId = false, $User = null)
    {
        if (is_null($User)) {
            $User = QUI::getUserBySession();
        }

        // Wenn der übergebene Benutzer = der Session Benutzer ist
        // Wird ihm der Zugriff erlaubt
        if (QUI::getUserBySession()->getId() == $User->getId()) {
            return;
        }

        if ($User->isSU()) {
            return;
        }

        if (QUI::getUsers()->isSystemUser($User)) {
            return;
        }

        if ($clientId === false) {
            throw new QUI\Permissions\Exception(
                QUI::getLocale()->get('quiqqer/system', 'exception.no.permission'),
                403
            );
        }

        $result = QUI::getDataBase()->fetch(array(
            'from'  => QUI\OAuth\Setup::getTable('oauth_clients'),
            'where' => array(
                'client_id' => $clientId
            )
        ));

        if (!isset($result[0])) {
            throw new QUI\Permissions\Exception(
                QUI::getLocale()->get('quiqqer/system', 'exception.no.permission'),
                403
            );
        }

        if ($User->getId() != $result[0]['user_id']) {
            throw new QUI\Permissions\Exception(
                QUI::getLocale()->get('quiqqer/system', 'exception.no.permission'),
                403
            );
        };
    }
}

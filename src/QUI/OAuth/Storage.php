<?php

/**
 * This file contains QUI\OAuth\Storage
 */

namespace QUI\OAuth;

use BaconQrCode\Exception\InvalidArgumentException;
use QUI;
use OAuth2;

/**
 * Class Storage
 *
 * QUIQQER PDO Storage for bshaffer/oauth2-server-php
 */
class Storage extends OAuth2\Storage\Pdo
{
    /**
     * @param mixed $connection
     * @param array $config
     *
     * @throws InvalidArgumentException
     */
    public function __construct($connection, $config = array())
    {
        try {
            $config = [
                'client_table'        => Setup::getTable('oauth_clients'),
                'access_token_table'  => Setup::getTable('oauth_access_tokens'),
                'refresh_token_table' => Setup::getTable('oauth_refresh_tokens'),
                'code_table'          => Setup::getTable('oauth_authorization_codes'),
                'user_table'          => QUI::getUsers()->table(),
                'jwt_table'           => Setup::getTable('oauth_jwt'),
                'jti_table'           => Setup::getTable('oauth_jti'),
                'scope_table'         => Setup::getTable('oauth_scopes'),
                'public_key_table'    => Setup::getTable('oauth_public_keys')
            ];
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);
        }

        parent::__construct($connection, $config);
    }

    /**
     * @param string $username
     * @return array|bool
     */
    public function getUserDetails($username)
    {
        try {
            $User = QUI::getUsers()->getUserByName($username);
        } catch (QUI\Exception $Exception) {
            return false;
        }

        return array_merge([
            'user_id' => $User->getId()
        ], $User->getAttributes());
    }
}

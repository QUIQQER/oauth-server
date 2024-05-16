<?php

namespace QUI\OAuth;

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
     */
    public function __construct($connection, $config = [])
    {
        try {
            $config = [
                'client_table' => Setup::getTable('oauth_clients'),
                'access_token_table' => Setup::getTable('oauth_access_tokens'),
                'refresh_token_table' => Setup::getTable('oauth_refresh_tokens'),
                'code_table' => Setup::getTable('oauth_authorization_codes'),
                'user_table' => QUI::getUsers()->table(),
                'jwt_table' => Setup::getTable('oauth_jwt'),
//                'jti_table'           => Setup::getTable('oauth_jti'),
                'scope_table' => Setup::getTable('oauth_scopes'),
//                'public_key_table'    => Setup::getTable('oauth_public_keys')
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
    public function getUserDetails($username): bool|array
    {
        try {
            $User = QUI::getUsers()->getUserByName($username);
        } catch (QUI\Exception) {
            return false;
        }

        return array_merge([
            'user_id' => $User->getUUID()
        ], $User->getAttributes());
    }
}

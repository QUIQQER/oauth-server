<?php

/**
 * This file contains QUI\OAuth\Storage
 */
namespace QUI\OAuth;

use QUI;
use OAuth2;

/**
 * Class Authorization
 * @package QUI\OAuth
 */
class Storage extends OAuth2\Storage\Pdo
{
    /**
     * Authorization constructor.
     */
    public function __construct()
    {
        $this->db = QUI::getPDO();

        $this->config = array(
            'client_table'        => Setup::getTable('oauth_clients'),
            'access_token_table'  => Setup::getTable('oauth_access_tokens'),
            'refresh_token_table' => Setup::getTable('oauth_refresh_tokens'),
            'code_table'          => Setup::getTable('oauth_authorization_codes'),
            'user_table'          => Setup::getTable('oauth_users'),
            'jwt_table'           => Setup::getTable('oauth_jwt'),
            'jti_table'           => Setup::getTable('oauth_jti'),
            'scope_table'         => Setup::getTable('oauth_scopes'),
            'public_key_table'    => Setup::getTable('oauth_public_keys')
        );
    }

    /**
     * @param $username
     * @param $password
     * @return bool
     */
    public function checkUserCredentials($username, $password)
    {
        try {
            $User = QUI::getUsers()->getUserByName($username);
        } catch (QUI\Exception $Exception) {
            return false;
        }

        return $User->checkPassword($password);
    }

    /**
     * @param $username
     * @return array|bool
     */
    public function getUserDetails($username)
    {
        try {
            $User = QUI::getUsers()->getUserByName($username);
        } catch (QUI\Exception $Exception) {
            return false;
        }

        return $User->getAttributes();
    }
}

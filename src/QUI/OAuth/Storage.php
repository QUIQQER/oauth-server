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
     * Use a timing-safe, case-sensitive comparison for confidential clients.
     *
     * @param string $client_id
     * @param string|null $client_secret
     */
    public function checkClientCredentials($client_id, $client_secret = null): bool
    {
        $client = $this->getClientDetails($client_id);

        if (!is_array($client) || !is_string($client_secret)) {
            return false;
        }

        return hash_equals((string)$client['client_secret'], $client_secret);
    }

    /**
     * @param string $client_id
     * @return array|false
     */
    public function getClientDetails($client_id): array|false
    {
        $client = parent::getClientDetails($client_id);

        if (!is_array($client) || !hash_equals((string)$client['client_id'], $client_id)) {
            return false;
        }

        return $client;
    }

    /**
     * @param string $access_token
     * @return array|false
     */
    public function getAccessToken($access_token): array|false
    {
        $token = parent::getAccessToken($access_token);

        if (!is_array($token) || !hash_equals((string)$token['access_token'], $access_token)) {
            return false;
        }

        return $token;
    }

    /**
     * @param string $refresh_token
     * @return array|false
     */
    public function getRefreshToken($refresh_token): array|false
    {
        $token = parent::getRefreshToken($refresh_token);

        if (!is_array($token) || !hash_equals((string)$token['refresh_token'], $refresh_token)) {
            return false;
        }

        return $token;
    }

    /**
     * @param string $code
     * @return array|false
     */
    public function getAuthorizationCode($code): array|false
    {
        $authorizationCode = parent::getAuthorizationCode($code);

        if (
            !is_array($authorizationCode)
            || !hash_equals((string)$authorizationCode['authorization_code'], $code)
        ) {
            return false;
        }

        return $authorizationCode;
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

<?php

/**
 * This file contains QUI\OAuth\Server
 */
namespace QUI\OAuth;

use QUI;

/**
 * Class Server
 * oauth server for QUIQQER
 *
 * @package QUI\OAuth
 */
class Setup
{
    /**
     * Return the real table name
     *
     * @param string $table
     * @return string
     * @throws QUI\Exception
     */
    public static function getTable($table)
    {
        switch ($table) {
            case 'oauth_clients':
            case 'oauth_access_tokens':
            case 'oauth_refresh_tokens':
            case 'oauth_authorization_codes':
            case 'oauth_users':
            case 'oauth_jwt':
            case 'oauth_jti':
            case 'oauth_scopes':
            case 'oauth_public_keys':
                return QUI::getDBTableName($table);
                break;
        }

        throw new QUI\Exception('unknown table');
    }

    /**
     * Generates the database tables
     */
    public static function execute()
    {
        $query = "
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_clients') . " (
                client_id VARCHAR(80) NOT NULL, 
                client_secret VARCHAR(80), 
                redirect_uri VARCHAR(2000) NOT NULL, 
                grant_types VARCHAR(80), 
                scope VARCHAR(100), 
                user_id INT(11) NOT NULL, 
                CONSTRAINT clients_client_id_pk PRIMARY KEY (client_id)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_access_tokens') . " (
                access_token VARCHAR(40) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                user_id INT(11), 
                expires TIMESTAMP NOT NULL, 
                scope VARCHAR(2000), 
                CONSTRAINT access_token_pk PRIMARY KEY (access_token)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_authorization_codes') . " (
                authorization_code VARCHAR(40) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                user_id INT(11), 
                redirect_uri VARCHAR(2000), 
                expires TIMESTAMP NOT NULL, 
                scope VARCHAR(2000), 
                CONSTRAINT auth_code_pk PRIMARY KEY (authorization_code)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_refresh_tokens') . " (
                refresh_token VARCHAR(40) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                user_id INT(11), 
                expires TIMESTAMP NOT NULL, 
                scope VARCHAR(2000), 
                CONSTRAINT refresh_token_pk PRIMARY KEY (refresh_token)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_scopes') . " (scope TEXT, is_default BOOLEAN);
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_jwt') . " (
                client_id VARCHAR(80) NOT NULL, 
                subject VARCHAR(80), 
                public_key VARCHAR(2000), 
                CONSTRAINT jwt_client_id_pk PRIMARY KEY (client_id)
            );
        ";

        QUI::getDataBase()->getPDO()->query($query);
    }
}

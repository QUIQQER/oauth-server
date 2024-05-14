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
    public static function getTable(string $table): string
    {
        switch ($table) {
            case 'oauth_clients':
            case 'oauth_access_tokens':
            case 'oauth_refresh_tokens':
            case 'oauth_authorization_codes':
            case 'oauth_jwt':
            case 'oauth_scopes':
            case 'oauth_access_limits':
                return QUI::getDBTableName($table);
        }

        throw new QUI\Exception('unknown table');
    }

    /**
     * Get all tables with a reference to a specific OAuth client
     *
     * @return array
     */
    public static function getClientTables(): array
    {
        return [
            QUI::getDBTableName('oauth_clients'),
            QUI::getDBTableName('oauth_access_tokens'),
            QUI::getDBTableName('oauth_refresh_tokens'),
            QUI::getDBTableName('oauth_authorization_codes'),
            QUI::getDBTableName('oauth_jwt'),
            QUI::getDBTableName('oauth_access_limits')
        ];
    }

    /**
     * Generates the database tables
     */
    public static function execute(): void
    {
        $query = "
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_clients') . " (
                name VARCHAR(250) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                client_secret VARCHAR(80), 
                redirect_uri VARCHAR(2000) NOT NULL, 
                grant_types VARCHAR(80), 
                scope VARCHAR(4000), 
                scope_restrictions TEXT NULL DEFAULT NULL,
                user_id VARCHAR(50) NOT NULL, 
                c_date INT(11) NOT NULL, 
                CONSTRAINT clients_client_id_pk PRIMARY KEY (client_id)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_access_tokens') . " (
                access_token VARCHAR(40) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                user_id VARCHAR(50), 
                expires TIMESTAMP NOT NULL, 
                scope VARCHAR(2000), 
                CONSTRAINT access_token_pk PRIMARY KEY (access_token)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_authorization_codes') . " (
                authorization_code VARCHAR(40) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                user_id VARCHAR(50), 
                redirect_uri VARCHAR(2000), 
                expires TIMESTAMP NOT NULL, 
                scope VARCHAR(2000), 
                CONSTRAINT auth_code_pk PRIMARY KEY (authorization_code)
            );
            
            CREATE TABLE IF NOT EXISTS " . self::getTable('oauth_refresh_tokens') . " (
                refresh_token VARCHAR(40) NOT NULL, 
                client_id VARCHAR(80) NOT NULL, 
                user_id VARCHAR(50), 
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

        QUI::getDataBase()->table()->addColumn(self::getTable('oauth_clients'), [
            'name' => 'VARCHAR(250) NOT NULL',
            'client_id' => 'VARCHAR(80) NOT NULL',
            'client_secret' => 'VARCHAR(80)',
            'redirect_uri' => 'VARCHAR(2000) NOT NULL DEFAULT \'\'',
            'grant_types' => 'VARCHAR(80)',
            'scope' => 'VARCHAR(4000)',
            'scope_restrictions' => 'TEXT NULL DEFAULT NULL',
            'user_id' => 'VARCHAR(50) NOT NULL',
            'c_date' => 'INT(11) NOT NULL'
        ]);
    }
}

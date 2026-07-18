<?php

namespace QUI\OAuth;

use QUI;

class Setup
{
    private const TABLES = [
        'oauth_clients',
        'oauth_access_tokens',
        'oauth_refresh_tokens',
        'oauth_authorization_codes',
        'oauth_jwt',
        'oauth_scopes',
        'oauth_access_limits'
    ];

    /**
     * Return the configured table name for an OAuth table.
     *
     * @throws QUI\Exception
     */
    public static function getTable(string $table): string
    {
        if (!in_array($table, self::TABLES, true)) {
            throw new QUI\Exception('unknown table');
        }

        return QUI::getDBTableName($table);
    }

    /**
     * Get all tables with a reference to a specific OAuth client.
     *
     * @return array<int, string>
     */
    public static function getClientTables(): array
    {
        return array_map(
            static fn(string $table): string => self::getTable($table),
            [
                'oauth_clients',
                'oauth_access_tokens',
                'oauth_refresh_tokens',
                'oauth_authorization_codes',
                'oauth_jwt',
                'oauth_access_limits'
            ]
        );
    }

    /**
     * Verify that package setup imported the portable database.xml schema.
     *
     * @throws QUI\Exception
     */
    public static function execute(): void
    {
        $tables = array_map(
            static fn(string $table): string => self::getTable($table),
            self::TABLES
        );

        if (!QUI::getSchemaManager()->tablesExist($tables)) {
            throw new QUI\Exception('OAuth database schema is incomplete');
        }
    }
}

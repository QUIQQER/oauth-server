<?php

namespace QUI\OAuth;

use Doctrine\DBAL\Schema\ColumnDiff;
use Doctrine\DBAL\Schema\TableDiff;
use Doctrine\DBAL\Types\Type;
use Doctrine\DBAL\Types\Types;
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

    private const EXPIRATION_TABLES = [
        'oauth_access_tokens',
        'oauth_refresh_tokens',
        'oauth_authorization_codes'
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

        self::migrateExpirationColumns();
    }

    /**
     * Replace legacy MySQL timestamp definitions whose implicit ON UPDATE
     * clause resets token expiration whenever token metadata is changed.
     */
    private static function migrateExpirationColumns(): void
    {
        foreach (self::EXPIRATION_TABLES as $table) {
            self::migrateExpirationColumn(self::getTable($table));
        }
    }

    /**
     * @throws QUI\Exception
     */
    private static function migrateExpirationColumn(string $tableName): void
    {
        $SchemaManager = QUI::getSchemaManager();
        $Table = $SchemaManager->introspectTable($tableName);

        if (!$Table->hasColumn('expires')) {
            throw new QUI\Exception('OAuth database schema is incomplete');
        }

        $CurrentColumn = $Table->getColumn('expires');
        $ExpectedColumn = clone $CurrentColumn;
        $ExpectedColumn->setType(Type::getType(Types::DATETIME_MUTABLE));
        $ExpectedColumn->setNotnull(true);
        $ExpectedColumn->setDefault(null);

        $ColumnDiff = new ColumnDiff($CurrentColumn, $ExpectedColumn);

        if ($ColumnDiff->countChangedProperties() === 0) {
            return;
        }

        $SchemaManager->alterTable(new TableDiff(
            $Table,
            changedColumns: ['expires' => $ColumnDiff]
        ));
    }
}

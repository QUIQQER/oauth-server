<?php

/**
 * This file contains QUI\OAuth\Package
 */
namespace QUI\OAuth;

use QUI;

/**
 * Class Package
 * @package QUI\OAuth
 */
class Package
{
    /**
     * @return string
     */
    public static function getDataBaseTableNames($table)
    {
        switch ($table) {
            case "oauth_sessions":
            case "oauth_scopes":
            case "oauth_clients":
            case "oauth_access_tokens":
            case "oauth_refresh_tokens":
            case "oauth_auth_codes":
            case "oauth_access_token_scopes":
            case "oauth_auth_code_scopes":
            case "oauth_session_scopes":
                return QUI::getDBTableName($table);
                break;
        }

        return false;
    }
}

<?php

namespace QUI\OAuth;

use PDO;
use QUI;

/**
 * Creates the third-party OAuth storage at its required native PDO boundary.
 *
 * All package-owned database operations use Doctrine DBAL. The upstream
 * bshaffer/oauth2-server-php PDO storage requires a native PDO instance and
 * performs its own parameterized storage queries internally.
 */
class StorageFactory
{
    /**
     * @throws Exception
     */
    public static function create(): Storage
    {
        $nativeConnection = QUI::getDataBaseConnection()->getNativeConnection();

        if (!$nativeConnection instanceof PDO) {
            throw new Exception('The OAuth storage requires a native PDO connection.');
        }

        return new Storage($nativeConnection);
    }
}

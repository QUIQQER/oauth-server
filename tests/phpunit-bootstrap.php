<?php

if (!defined('QUIQQER_SYSTEM')) {
    define('QUIQQER_SYSTEM', true);
}

if (!defined('QUIQQER_AJAX')) {
    define('QUIQQER_AJAX', true);
}

if (!defined('SYSTEM_INTERN')) {
    define('SYSTEM_INTERN', true);
}

require_once __DIR__ . '/../../../../bootstrap.php';

if (!class_exists(QUI\FrontendUsers\Controls\Profile\AbstractProfileControl::class)) {
    require_once __DIR__ . '/phpstan-shims/AbstractProfileControl.php';
}

require_once __DIR__ . '/Support/OAuthDatabaseTestCase.php';

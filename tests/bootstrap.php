<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// phpunit .
// phpunit --coverage-text .

$quiqqerPackageDir = dirname(dirname(__FILE__));
$packageDir        = dirname(dirname($quiqqerPackageDir));

// include quiqqer bootstrap for tests
require $packageDir . '/quiqqer/quiqqer/tests/bootstrap.php';

QUI\Autoloader::$ComposerLoader->add('QUITest', dirname(__FILE__) . '/');

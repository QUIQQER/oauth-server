<?php

/**
 * This file contains QUI\OAuth\RestProvider
 */
namespace QUI\OAuth;

use QUI;
use QUI\REST\Server;

/**
 * Class RestProvider
 *
 * @package QUI\OAuth
 */
class RestProvider implements QUI\REST\ProviderInterface
{
    /**
     * @param Server $Server
     */
    public function register(Server $Server)
    {
        $Slim = $Server->getSlim();

        $Slim->group('/oauth', function () {
            /* @var $this \Slim\App */
            $this->get('/authorize', function () {

            });

            /* @var $this \Slim\App */
            $this->get('/token', function () {

            });
        });
    }
}
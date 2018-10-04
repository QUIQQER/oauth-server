<?php

/**
 * This file contains QUI\OAuth\RestProvider
 */

namespace QUI\OAuth;

use QUI;
use QUI\REST\Server;
use OAuth2;
use QUI\OAuth\Server as OAuth2Server;

use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use Psr\Http\Message\ResponseInterface as ResponseInterface;

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
        $Slim   = $Server->getSlim();
        $Server = OAuth2Server::getInstance()->getOAuth2Server();

        $Slim->group('/oauth', function () use ($Server) {
            /* @var $this \Slim\App */

            // @todo the /authorize endpoint functionality has to be rewritten
            // as soon as quiqqer/oauth-server allows `Authorization Code` grant type
//            $this->post('/authorize', function (
//                RequestInterface $Request,
//                ResponseInterface $Response,
//                $args
//            ) use ($Server) {
//                if (!$Server->verifyResourceRequest(OAuth2\Request::createFromGlobals())) {
//                    $Server->getResponse()->send();
//                    die;
//                }
//
//                return $Response->withStatus(200)
//                    ->withHeader('Content-Type', 'application/json')
//                    ->write(json_encode(['success' => true]));
//            });

            $this->post('/token', function () use ($Server) {
                $Server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
            });
        });
    }
}

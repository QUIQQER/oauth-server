<?php

namespace QUI\OAuth;

use Psr\Http\Message\ResponseInterface as ResponseInterface;
use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use QUI;
use QUI\REST\Response;
use QUI\REST\Server;
use OAuth2;
use QUI\OAuth\Server as OAuth2Server;
use Slim\Routing\RouteCollectorProxy;

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
        $Slim         = $Server->getSlim();
        $OAuth2Server = OAuth2Server::getInstance()->getOAuth2Server();

        $Slim->group('/oauth', function (RouteCollectorProxy $RouteCollector) use ($OAuth2Server) {
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

            $RouteCollector->post('/token', function () use ($OAuth2Server) {
                $OAuth2Server->handleTokenRequest(OAuth2\Request::createFromGlobals())->send();
            });
        });

        // Test path
        $Slim->post('/quiqqer_oauth_test', function (RequestInterface $Request, ResponseInterface $Response, $args) {
            /** @var Response $Response */
            $Response->withHeader('Content-Type', 'application/json');

            return $Response->write(\json_encode([
                'success' => true
            ]));
        });
    }
}

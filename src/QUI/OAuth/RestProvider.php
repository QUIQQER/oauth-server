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
    public function register(Server $Server): void
    {
        $Slim = $Server->getSlim();
        $OAuth2Server = OAuth2Server::getInstance()->getOAuth2Server();

        $Slim->group('/oauth', function (RouteCollectorProxy $RouteCollector) use ($OAuth2Server) {
            // @todo the /authorize endpoint functionality has to be rewritten
            // as soon as quiqqer/oauth-server allows `Authorization Code` grant type

            $RouteCollector->post(
                '/token',
                function (RequestInterface $Request, ResponseInterface $Response, $args) use ($OAuth2Server) {
                    $OAuthServerResponse = new OAuth2\Response();

                    $OAuth2Server->handleTokenRequest(
                        RequestFactory::fromPsr($Request),
                        $OAuthServerResponse
                    );

                    $RestResponse = new Response(
                        $OAuthServerResponse->getStatusCode(),
                        $OAuthServerResponse->getHttpHeaders(),
                        $OAuthServerResponse->getResponseBody(),
                        $OAuthServerResponse->version
                    );

                    return $RestResponse->withHeader('Content-Type', 'application/json');
                }
            );
        });

        // Test path
        $Slim->post('/quiqqer_oauth_test', function (RequestInterface $Request, ResponseInterface $Response, $args) {
            /** @var Response $Response */
            $Response = $Response->withHeader(
                'Content-Type',
                'application/json'
            );

            return $Response->write('{"success":true}');
        });
    }

    /**
     * Get file containing OpenApi definition for this API.
     *
     * @return string|false - Absolute file path or false if no definition exists
     */
    public function getOpenApiDefinitionFile(): bool|string
    {
        return false;
    }

    /**
     * Get unique internal API name.
     *
     * This is required for requesting specific data about an API (i.e. OpenApi definition).
     *
     * @return string - Only letters; no other characters!
     */
    public function getName(): string
    {
        return 'OAuthServer';
    }

    /**
     * Get title of this API.
     *
     * @param QUI\Locale|null $Locale (optional)
     * @return string
     */
    public function getTitle(?QUI\Locale $Locale = null): string
    {
        if (empty($Locale)) {
            $Locale = QUI::getLocale();
        }

        return $Locale->get('quiqqer/oauth-server', 'RestProvider.title');
    }
}

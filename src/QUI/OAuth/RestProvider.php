<?php

namespace QUI\OAuth;

use Psr\Http\Message\ResponseInterface as ResponseInterface;
use Psr\Http\Message\ServerRequestInterface as RequestInterface;
use QUI;
use QUI\REST\Response;
use QUI\REST\Server;
use OAuth2;
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
        $AuthorizationEndpoint = new AuthorizationEndpoint();
        $TokenEndpoint = new TokenEndpoint();

        $Slim->group(
            '/oauth',
            function (RouteCollectorProxy $RouteCollector) use ($AuthorizationEndpoint, $TokenEndpoint) {
                $RouteCollector->map(
                    ['GET', 'POST'],
                    '/authorize',
                    static function (
                        RequestInterface $Request,
                        ResponseInterface $Response,
                        array $args
                    ) use ($AuthorizationEndpoint) {
                        return $AuthorizationEndpoint->handle($Request);
                    }
                );

                $RouteCollector->post(
                    '/token',
                    static function (
                        RequestInterface $Request,
                        ResponseInterface $Response,
                        array $args
                    ) use ($TokenEndpoint) {
                        return $TokenEndpoint->handle($Request);
                    }
                );

                $RouteCollector->post(
                    '/revoke',
                    static function (
                        RequestInterface $Request,
                        ResponseInterface $Response,
                        array $args
                    ) use ($TokenEndpoint) {
                        return $TokenEndpoint->revoke($Request);
                    }
                );
            }
        );

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

    public static function fromOAuthResponse(OAuth2\Response $OAuthResponse): Response
    {
        $RestResponse = new Response(
            $OAuthResponse->getStatusCode(),
            $OAuthResponse->getHttpHeaders(),
            $OAuthResponse->getResponseBody(),
            $OAuthResponse->version
        );

        return $RestResponse->withHeader('Content-Type', 'application/json; charset=utf-8');
    }
}

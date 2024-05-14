<?php

namespace QUI\OAuth\Middleware;

use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use QUI;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Http\Message\ResponseInterface as Response;

class RestMiddleware
{
    /**
     * Example middleware invokable class
     *
     * @param Request $Request PSR7 request
     * @param RequestHandler $RequestHandler PSR7 response
     *
     * @return Response
     */
    public function __invoke(Request $Request, RequestHandler $RequestHandler): Response
    {
        try {
            $this->validateRequest($Request);
            return $RequestHandler->handle($Request);
        } catch (InvalidRequestException $Exception) {
            $Response = new QUI\REST\Response($Exception->getCode());

            $Response->getBody()->write(json_encode([
                'error'             => $Exception->getMessage(),
                'error_description' => $Exception->getErrorDescription(),
                'error_code'        => $Exception->getCode()
            ]));

            return $Response;
        }
    }

    /**
     * Validate a REST API request
     *
     * Throws an exception if the request is invalid
     *
     * @param Request $Request PSR7 request
     * @return void
     * @throws InvalidRequestException
     */
    protected function validateRequest(Request $Request): void
    {
        try {
            $RESTConfig  = QUI::getPackage('quiqqer/rest')->getConfig();
            $OAuthConfig = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        } catch (Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new InvalidRequestException(
                'system_error',
                'System error. Please contact an administrator.',
                500
            );
        }

        $basePath = ltrim($RESTConfig->getValue('general', 'basePath'), '/');
        $query    = $Request->getQueryParams();
        $endpoint = '/'.str_replace($basePath, '', ltrim($query['_url'], '/'));

        // Requests to /oauth endpoints do not require special authentication / permissions
        if (mb_strpos($endpoint, '/oauth') === 0) {
            return;
        }

        // Check if OAuth2 authentication is required for the endpoint (scope)
        $scope           = ResourceController::parseScopeFromEndpoint($endpoint);
        $protectedScopes = $OAuthConfig->get('general', 'protected_scopes');

        if (!empty($protectedScopes)) {
            $protectedScopes = json_decode($protectedScopes, true);

            if (isset($protectedScopes[$scope]) && !$protectedScopes[$scope]) {
                // do not verify request
                return;
            }
        }

        // This constant tells the OAuth client handler to ignore permission checks
        define('OAUTH_REST_REQUEST', 1);

        // Verify resource request
        $OAuth2Server = QUI\OAuth\Server::getInstance()->getOAuth2Server();
        /** @var ResourceController $ResourceController */
        $ResourceController = $OAuth2Server->getResourceController();
        $ResourceController->verify($endpoint, ServerRequest::fromGlobals());
    }
}

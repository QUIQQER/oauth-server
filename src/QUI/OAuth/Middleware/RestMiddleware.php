<?php

namespace QUI\OAuth\Middleware;

use GuzzleHttp\Psr7\ServerRequest;
use QUI;

class RestMiddleware
{
    /**
     * Example middleware invokable class
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $Request PSR7 request
     * @param  \Psr\Http\Message\ResponseInterface $Response PSR7 response
     * @param  callable $next Next middleware
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke($Request, $Response, $next)
    {
        try {
            $this->validateRequest($Request);
        } catch (InvalidRequestException $Exception) {
            $Response->getBody()->write(json_encode([
                'error'             => $Exception->getMessage(),
                'error_description' => $Exception->getErrorDescription(),
                'error_code'        => $Exception->getCode()
            ]));

            return $Response;
        }

        return $next($Request, $Response);
    }

    /**
     * Validate a REST API request
     *
     * @param  \Psr\Http\Message\ServerRequestInterface $Request PSR7 request
     * @return void
     * @throws InvalidRequestException
     */
    protected function validateRequest($Request)
    {
        try {
            $RESTConfig  = QUI::getPackage('quiqqer/rest')->getConfig();
            $OAuthConfig = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        } catch (\Exception $Exception) {
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

        // Verfiy resource request
        $OAuth2Server = QUI\OAuth\Server::getInstance()->getOAuth2Server();
        /** @var ResourceController $ResourceContoller */
        $ResourceContoller = $OAuth2Server->getResourceController();
        $ResourceContoller->verify($endpoint, ServerRequest::fromGlobals());
    }
}

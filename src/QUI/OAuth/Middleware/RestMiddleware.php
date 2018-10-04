<?php

namespace QUI\OAuth\Middleware;

use QUI;
use OAuth2;

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
            $Config = QUI::getPackage('quiqqer/rest')->getConfig();
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new InvalidRequestException(
                'system_error',
                'System error. Please contact an administrator.',
                500
            );
        }

        $basePath = ltrim($Config->getValue('general', 'basePath'), '/');
        $query    = $Request->getQueryParams();
        $endpoint = '/'.str_replace($basePath, '', ltrim($query['_url'], '/'));

        // Requests to /oauth endpoints do not require special authentication / permissions
        if (mb_strpos($endpoint, '/oauth') === 0) {
            return;
        }

//        // @todo gefährlich? Wird zB für getOAuthClient permission benötigt
        if (!defined('SYSTEM_INTERN')) {
            define('SYSTEM_INTERN', 1);
        }

        // Verfiy resource request
        $OAuth2Server = QUI\OAuth\Server::getInstance()->getOAuth2Server();
        /** @var ResourceController $ResourceContoller */
        $ResourceContoller = $OAuth2Server->getResourceController();
        $ResourceContoller->verify($endpoint, OAuth2\Request::createFromGlobals());
    }
}

<?php

/**
 * This file contains QUI\OAuth\EventHandler
 */

namespace QUI\OAuth;

use QUI;
use QUI\Cron\Manager as CronManager;
use QUI\REST\Server as RestServer;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class Server
 * oauth server for QUIQQER
 *
 * @package QUI\OAuth
 */
class EventHandler
{
    /**
     * @param QUI\Package\Package $Package
     */
    public static function onPackageSetup(QUI\Package\Package $Package): void
    {
        if ($Package->getName() !== 'quiqqer/oauth-server') {
            return;
        }

        Setup::execute();
    }

    /**
     * quiqqer/quiqqer: onPackageInstall
     *
     * @param QUI\Package\Package $Package
     */
    public static function onPackageInstall(QUI\Package\Package $Package): void
    {
        if ($Package->getName() !== 'quiqqer/oauth-server') {
            return;
        }

        try {
            self::createCrons();
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);
        }
    }

    /**
     * Create all crons
     *
     * @return void
     * @throws \QUI\Exception
     */
    protected static function createCrons(): void
    {
        $Cron = new CronManager();

        $Cron->add(
            '\QUI\OAuth\Clients\Handler::cleanupAccessTokens',
            '0',
            '0',
            '*',
            '*',
            '*'
        );
    }

    /**
     * quiqqer/quiqqer: onRequest
     *
     * Add REST API OAuth2 middleware to validate requests
     *
     * @param QUI\Rewrite $Rewrite
     * @param string $url
     *
     * @throws \QUI\Exception
     */
    public static function onRequest(QUI\Rewrite $Rewrite, string $url): void
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();

        if (!$Config?->getValue('general', 'active')) {
            return;
        }

        $DiscoveryResponse = self::getDiscoveryResponse(QUI::getRequest(), $url);

        if ($DiscoveryResponse) {
            $DiscoveryResponse->send();
            exit;
        }

        if (!self::isRestRequestEvent()) {
            return;
        }

        $Server = RestServer::getCurrentInstance();
        $Server->getSlim()->add(new QUI\OAuth\Middleware\RestMiddleware());
    }

    /**
     * Handle OAuth discovery on the origin root, outside the REST base path.
     */
    public static function getDiscoveryResponse(
        Request $Request,
        string $url,
        ?RestServer $Server = null
    ): ?Response {
        $path = '/' . trim($url, '/');

        if (
            $path !== '/.well-known/oauth-authorization-server'
            && $path !== '/.well-known/oauth-protected-resource'
        ) {
            return null;
        }

        if (!$Request->isMethod(Request::METHOD_GET)) {
            return new JsonResponse(
                ['error' => 'method_not_allowed'],
                Response::HTTP_METHOD_NOT_ALLOWED,
                [
                    'Allow' => Request::METHOD_GET,
                    'Cache-Control' => 'no-store'
                ]
            );
        }

        $Server ??= RestServer::getCurrentInstance();
        $metadata = $path === '/.well-known/oauth-authorization-server'
            ? Metadata::authorizationServer($Server)
            : Metadata::protectedResource($Server);

        return new JsonResponse(
            $metadata,
            Response::HTTP_OK,
            ['Cache-Control' => 'no-store']
        );
    }

    /**
     * Check if the current onRequest event belongs to the REST API.
     */
    protected static function isRestRequestEvent(): bool
    {
        try {
            $requestPath = QUI::getRequest()->getPathInfo();
            $restPath = QUI::getPackage('quiqqer/rest')->getConfig()?->get('general', 'basePath');
        } catch (QUI\Exception $Exception) {
            QUI\System\Log::writeException($Exception);
            return false;
        }

        if (!is_string($restPath)) {
            return false;
        }

        return self::isRestRequestPath($requestPath, $restPath);
    }

    /**
     * Check a request path against the configured REST base path.
     */
    protected static function isRestRequestPath(string $requestPath, string $restPath): bool
    {
        $restPath = '/' . trim($restPath, '/');

        if ($restPath === '/') {
            return false;
        }

        return $requestPath === $restPath
            || str_starts_with($requestPath, $restPath . '/');
    }

    /**
     * quiqqer/rest: onQuiqqerRestLoadOpenApiSpecification
     *
     * @param string $apiName
     * @param array<string, mixed> $specification
     * @return void
     */
    public static function onQuiqqerRestLoadOpenApiSpecification(string $apiName, array &$specification): void
    {
        try {
            $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();

            if (!$Config?->getValue('general', 'active')) {
                return;
            }

            // Extend OpenApi specification by OAuth2 information
            if (empty($specification['components']['securitySchemes'])) {
                $specification['components']['securitySchemes'] = [];
            }

            $baseUrl = QUI\REST\Server::getInstance()->getBasePathWithHost();
            $scopes = array_fill_keys(QUI\REST\Server::getInstance()->getEntryPoints(), '');
            $specification['components']['securitySchemes']['oAuth2'] = [
                'type' => 'oauth2',
                'description' => 'OAuth 2 Authorization Code with PKCE for users and Client Credentials for services.',
                'flows' => [
                    'authorizationCode' => [
                        'authorizationUrl' => $baseUrl . 'oauth/authorize',
                        'tokenUrl' => $baseUrl . 'oauth/token',
                        'scopes' => $scopes
                    ],
                    'clientCredentials' => [
                        'tokenUrl' => $baseUrl . 'oauth/token',
                        'scopes' => $scopes
                    ]
                ]
            ];

            if (empty($specification['components']['responses'])) {
                $specification['components']['responses'] = [];
            }

            $specification['components']['responses']['OAuth2Error'] = [
                'description' => 'OAuth 2 Middleware error',
                'content' => [
                    'application/json' => [
                        'schema' => [
                            'type' => 'object',
                            'properties' => [
                                'error' => [
                                    'type' => 'string',
                                    'description' => 'Error short handle.'
                                ],
                                'error_description' => [
                                    'type' => 'string',
                                    'description' => 'Error description.'
                                ],
                                'error_code' => [
                                    'type' => 'integer',
                                    'description' => 'Error code.'
                                ]
                            ]
                        ]
                    ]
                ]
            ];

            foreach ($specification['paths'] as $path => $methods) {
                foreach ($methods as $method => $methodData) {
                    if (empty($methodData['responses']['4XX'])) {
                        $methodData['responses']['4XX'] = [
                            '$ref' => '#/components/responses/OAuth2Error'
                        ];
                    }

                    if (empty($methodData['security'])) {
                        $methodData['security'] = [];
                    }

                    $methodData['security'][] = [
                        'oAuth2' => []
                    ];

                    $specification['paths'][$path][$method] = $methodData;
                }
            }
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);
        }
    }
}

<?php

/**
 * This file contains QUI\OAuth\EventHandler
 */

namespace QUI\OAuth;

use QUI;
use QUI\Cron\Manager as CronManager;

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
        $Conf = QUI::getPackage('quiqqer/oauth-server')->getConfig();

        if (!$Conf->getValue('general', 'active')) {
            return;
        }

        $Server = QUI\REST\Server::getCurrentInstance();
        $Server->getSlim()->add(new QUI\OAuth\Middleware\RestMiddleware());
    }

    /**
     * quiqqer/rest: onQuiqqerRestLoadOpenApiSpecification
     *
     * @param string $apiName
     * @param array $specification
     * @return void
     */
    public static function onQuiqqerRestLoadOpenApiSpecification(string $apiName, array &$specification): void
    {
        try {
            $Conf = QUI::getPackage('quiqqer/oauth-server')->getConfig();

            if (!$Conf->getValue('general', 'active')) {
                return;
            }

            // Extend OpenApi specification by OAuth2 information
            if (empty($specification['components']['securitySchemes'])) {
                $specification['components']['securitySchemes'] = [];
            }

            $specification['components']['securitySchemes']['oAuth2'] = [
                'type'        => 'oauth2',
                'description' => 'This API uses OAuth 2 with the clientCredentials grant flow.',
                'flows'       => [
                    'clientCredentials' => [
                        'tokenUrl' => QUI\REST\Server::getInstance()->getBasePathWithHost().'oauth/token'
                    ],
                    'scopes'            => [] // @todo add scopes
                ]
            ];

            if (empty($specification['components']['responses'])) {
                $specification['components']['responses'] = [];
            }

            $specification['components']['responses']['OAuth2Error'] = [
                'description' => 'OAuth 2 Middleware error',
                'content'     => [
                    'application/json' => [
                        'schema' => [
                            'type'       => 'object',
                            'properties' => [
                                'error'             => [
                                    'type'        => 'string',
                                    'description' => 'Error short handle.'
                                ],
                                'error_description' => [
                                    'type'        => 'string',
                                    'description' => 'Error description.'
                                ],
                                'error_code'        => [
                                    'type'        => 'integer',
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

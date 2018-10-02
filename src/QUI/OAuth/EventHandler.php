<?php

/**
 * This file contains QUI\OAuth\EventHandler
 */
namespace QUI\OAuth;

use QUI;

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
    public static function onPackageSetup(QUI\Package\Package $Package)
    {
        if ($Package->getName() !== 'quiqqer/oauth-server') {
            return;
        }

        Setup::execute();
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
    public static function onRequest(QUI\Rewrite $Rewrite, $url)
    {
        $Conf = QUI::getPackage('quiqqer/oauth-server')->getConfig();

        if (!$Conf->getValue('general', 'active')) {
            return;
        }

        $Server = QUI\REST\Server::getCurrentInstance();
        $Server->getSlim()->add(new QUI\OAuth\Middleware\RestMiddleware());
    }
}

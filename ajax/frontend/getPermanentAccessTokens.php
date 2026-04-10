<?php

use QUI\OAuth\FrontendController;
use QUI\OAuth\FrontendException;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_frontend_getPermanentAccessTokens',
    /**
     * Gets all permanent access tokens of the current user.
     *
     * @return array[] - permanent access token data
     * @throws FrontendException
     */
    function () {
        return new FrontendController()->getPermanentAccessTokens(QUI::getUserBySession());
    },
    [],
    'Permission::checkAdminUser'
);

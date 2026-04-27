<?php

use QUI\OAuth\FrontendController;
use QUI\OAuth\FrontendException;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_frontend_deletePermanentAccessToken',
    /**
     * Deletes an OAuth client with client secret as permanent access token.
     *
     * @param string $uuid
     * @return void
     * @throws FrontendException
     */
    function ($uuid) {
        $FrontendController = new FrontendController();

        $FrontendController->deletePermanentAccessToken(QUI::getUserBySession(), $uuid);
    },
    [
        'id'
    ],
    'Permission::checkUser'
);

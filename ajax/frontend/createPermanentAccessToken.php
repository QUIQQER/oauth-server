<?php

use QUI\OAuth\FrontendController;
use QUI\OAuth\FrontendException;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_frontend_createPermanentAccessToken',
    /**
     * Creates a new OAuth client with client secret as permanent access token.
     *
     * @param ?string $title
     * @return string - permanent access token
     * @throws FrontendException
     */
    function (?string $title = null) {
        return new FrontendController()->createPermanentAccessToken(QUI::getUserBySession(), $title);
    },
    ['title'],
    'Permission::checkUser'
);

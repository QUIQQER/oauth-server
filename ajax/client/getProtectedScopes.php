<?php

/**
 * Return scope protection settings
 *
 * @return array
 * @throws \QUI\Exception
 */

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_getProtectedScopes',
    function () {
        $Conf = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $protectedScopes = $Conf->get('general', 'protected_scopes');

        if (!empty($protectedScopes)) {
            $protectedScopes = json_decode($protectedScopes, true);
        } else {
            $protectedScopes = [];
        }

        return $protectedScopes;
    },
    [],
    'Permission::checkAdminUser'
);

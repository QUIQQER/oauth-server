<?php

/**
 * Return scope protection settings
 *
 * @return array
 * @throws \QUI\Exception
 */

QUI::getAjax()->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_getProtectedScopes',
    function () {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $protectedScopes = $Config?->get('general', 'protected_scopes');

        if (!is_string($protectedScopes) || $protectedScopes === '') {
            return [];
        }

        $protectedScopes = json_decode($protectedScopes, true);

        return is_array($protectedScopes) ? $protectedScopes : [];
    },
    [],
    'Permission::checkAdminUser'
);

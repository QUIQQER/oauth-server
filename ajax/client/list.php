<?php

/**
 * Return all clients from the current user
 *
 * @return string
 */

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_list',
    function ($userId) {
        $list = QUI\OAuth\Clients\Handler::getOAuthClientsByUser(
            QUI::getUsers()->get($userId)
        );

        foreach ($list as $key => $entry) {
            if (empty($entry['name'])) {
                $list[$key]['name'] = '';
            }
        }

        return $list;
    },
    ['userId'],
    'Permission::checkAdminUser'
);

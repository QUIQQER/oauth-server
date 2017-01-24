<?php

/**
 * Return all clients from the current user
 *
 * @return string
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_list',
    function () {
        $list = QUI\OAuth\Clients\Handler::getOAuthClientsByUser(
            QUI::getUserBySession()
        );

        foreach ($list as $key => $entry) {
            if (empty($entry['name'])) {
                $list[$key]['name'] = '';
            }
        }

        return $list;
    }
);

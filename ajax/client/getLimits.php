<?php

use QUI\OAuth\Clients\Handler as ClientsHandler;

/**
 * Return all scope usage limits for an OAuth client
 *
 * @param int $clientId
 * @return array
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_getLimits',
    function ($clientId) {
        $limits = ClientsHandler::getClientLimits($clientId);
        $L = QUI::getLocale();

        foreach ($limits as $scope => $limitData) {
            if (empty($limitData['first_usage'])) {
                $limitData['first_usage'] = $L->get('quiqqer/oauth-server', 'label.never');
            } else {
                $limitData['first_usage'] = $L->formatDate($limitData['first_usage']);
            }

            if (empty($limitData['last_usage'])) {
                $limitData['last_usage'] = $L->get('quiqqer/oauth-server', 'label.never');
            } else {
                $limitData['last_usage'] = $L->formatDate($limitData['last_usage']);
            }

            $limits[$scope] = $limitData;
        }

        return $limits;
    },
    ['clientId'],
    'Permission::checkAdminUser'
);

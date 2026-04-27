<?php

namespace QUI\OAuth;

use QUI;
use QUI\Interfaces\Users\User as QuiUserInterface;
use QUI\Permissions\Permission as QuiPermission;

enum Permission: string
{
    case MANAGE_CLIENTS = 'quiqqer.oauth-server.manage_clients';
    case CREATE_PERMANENT_ACCESS_TOKEN_FOR_OWN_USER = 'quiqqer.oauth-server.create_permanent_access_token_for_own_user';
    case MAX_NUMBER_OF_PERMANENT_ACCESS_TOKENS = 'quiqqer.oauth-server.max_number_of_permanent_access_tokens';

    /**
     * @param QuiUserInterface|null $user - If null, the current session user is used
     * @return void
     * @throws QUI\Permissions\Exception
     */
    public function check(?QuiUserInterface $user = null): void
    {
        if ($user === null) {
            $user = QUI::getUserBySession();
        }

        QuiPermission::checkPermission($this->value, $user);
    }

    public function has(?QuiUserInterface $user = null): bool
    {
        if ($user === null) {
            $user = QUI::getUserBySession();
        }

        return QuiPermission::hasPermission($this->value, $user) !== false;
    }
}

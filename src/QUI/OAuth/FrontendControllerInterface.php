<?php

namespace QUI\OAuth;

use QUI\Interfaces\Users\User as QuiUserInterface;

interface FrontendControllerInterface
{
    public function createPermanentAccessToken(QuiUserInterface $user, ?string $title = null): string;

    /**
     * @param QuiUserInterface $user
     * @return array<array{token: string, title: string}>
     */
    public function getPermanentAccessTokens(QuiUserInterface $user): array;

    public function deletePermanentAccessToken(QuiUserInterface $user, string $oauthClientUuid): void;
}

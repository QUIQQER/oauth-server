<?php

namespace QUI\OAuth\Consent;

use QUI\Interfaces\Users\User;

final class Context
{
    /**
     * @param list<string> $requestedScopes
     */
    public function __construct(
        private readonly User $User,
        private readonly string $clientId,
        private readonly string $clientName,
        private readonly string $resource,
        private readonly array $requestedScopes
    ) {
    }

    public function getUser(): User
    {
        return $this->User;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getClientName(): string
    {
        return $this->clientName;
    }

    public function getResource(): string
    {
        return $this->resource;
    }

    /**
     * @return list<string>
     */
    public function getRequestedScopes(): array
    {
        return $this->requestedScopes;
    }
}

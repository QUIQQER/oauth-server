<?php

namespace QUI\OAuth;

final class DynamicClientRegistrationException extends \RuntimeException
{
    public function __construct(
        private readonly string $error,
        string $description,
        int $statusCode = 400
    ) {
        parent::__construct($description, $statusCode);
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getStatusCode(): int
    {
        return $this->getCode();
    }
}

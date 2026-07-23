<?php

namespace QUITest\QUI\OAuth\Unit;

use Psr\Http\Message\ServerRequestInterface;
use QUI\OAuth\Middleware\InvalidRequestException;
use QUI\OAuth\Middleware\RestMiddleware;

class RejectingRestMiddleware extends RestMiddleware
{
    protected function validateRequest(ServerRequestInterface $Request): void
    {
        throw new InvalidRequestException('insufficient_scope', 'Scope denied', 403);
    }
}

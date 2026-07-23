<?php

namespace QUITest\QUI\OAuth\Unit;

use Psr\Http\Message\ServerRequestInterface;
use QUI\OAuth\Middleware\RestMiddleware;

class AcceptingRestMiddleware extends RestMiddleware
{
    protected function validateRequest(ServerRequestInterface $Request): void
    {
    }
}

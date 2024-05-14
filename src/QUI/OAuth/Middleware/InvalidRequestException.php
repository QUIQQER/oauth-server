<?php

namespace QUI\OAuth\Middleware;

use QUI\OAuth\Exception;

class InvalidRequestException extends Exception
{
    protected string $errorDescription;

    /**
     * Constructor
     *
     * @param string $error - Error code (string representation)
     * @param string $errorDescription - Error description
     * @param integer $code - Error code (numeric representation)
     * @param array $context - [optional] Context data, which data
     */
    public function __construct($error, $errorDescription, $code = 0, array $context = [])
    {
        parent::__construct($error, $code, $context);
        $this->errorDescription = $errorDescription;
    }

    /**
     * Get Exception error description
     *
     * @return string
     */
    public function getErrorDescription(): string
    {
        return $this->errorDescription;
    }
}

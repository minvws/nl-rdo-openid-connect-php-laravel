<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services;

use Exception;
use Illuminate\Contracts\Support\Responsable;
use Jumbojett\OpenIDConnectClientException;

interface OpenIDConnectExceptionHandlerInterface
{
    public function handleExceptionWhileAuthenticate(OpenIDConnectClientException $exception): Responsable;
    public function handleExceptionWhileRequestUserInfo(OpenIDConnectClientException $exception): Responsable;
    public function handleException(Exception $exception): Responsable;
}

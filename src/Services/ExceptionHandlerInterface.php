<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services;

use Exception;
use Jumbojett\OpenIDConnectClientException;
use Symfony\Component\HttpFoundation\Response;

interface ExceptionHandlerInterface
{
    public function handleExceptionWhileAuthenticate(OpenIDConnectClientException $exception): Response;
    public function handleExceptionWhileRequestUserInfo(OpenIDConnectClientException $exception): Response;
    public function handleException(Exception $exception): Response;
}

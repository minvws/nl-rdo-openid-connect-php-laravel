<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Http\Responses;

use Symfony\Component\HttpFoundation\Response;

interface LoginResponseHandlerInterface
{
    public function handleLoginResponse(object $userInfo): Response;
}

<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Http\Responses;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

class LoginResponseHandler implements LoginResponseHandlerInterface
{
    #[\Override]
    public function handleLoginResponse(object $userInfo): Response
    {
        return new JsonResponse([
            'userInfo' => $userInfo,
        ]);
    }
}

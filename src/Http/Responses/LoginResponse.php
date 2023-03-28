<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Http\Responses;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class LoginResponse implements Responsable
{
    public function __construct(
        protected object $userInfo
    ) {
    }

    /**
     * Create an HTTP response that represents the object.
     *
     * @param Request $request
     * @return Response
     */
    public function toResponse($request): Response
    {
        return new JsonResponse([
            'userInfo' => $this->userInfo,
        ]);
    }
}

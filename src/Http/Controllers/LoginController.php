<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseHandlerInterface;
use MinVWS\OpenIDConnectLaravel\OpenIDConnectClient;
use MinVWS\OpenIDConnectLaravel\Services\ExceptionHandlerInterface;
use Symfony\Component\HttpFoundation\Response;

class LoginController extends Controller
{
    public function __construct(
        protected OpenIDConnectClient $client,
        protected ExceptionHandlerInterface $exceptionHandler,
        protected LoginResponseHandlerInterface $responseHandler,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        // This redirects to the client and handles the redirect back
        try {
            $this->client->setLoginHint($this->getLoginHint($request));
            $this->client->authenticate();
        } catch (OpenIDConnectClientException $e) {
            return $this->exceptionHandler->handleExceptionWhileAuthenticate($e);
        }

        // After the redirect back, we can get the user information
        try {
            $userInfo = $this->client->requestUserInfo();
            if (!is_object($userInfo)) {
                throw new OpenIDConnectClientException('Received user info is not an object');
            }
        } catch (OpenIDConnectClientException $e) {
            return $this->exceptionHandler->handleExceptionWhileRequestUserInfo($e);
        } catch (Exception $e) {
            return $this->exceptionHandler->handleException($e);
        }

        // Return the user information to response handler
        return $this->responseHandler->handleLoginResponse($userInfo);
    }

    /**
     * Get the login hint from the request.
     * @param Request $request
     * @return string|null
     */
    protected function getLoginHint(Request $request): ?string
    {
        $loginHint = $request->query('login_hint');
        if (!is_string($loginHint)) {
            return null;
        }

        return $loginHint;
    }
}

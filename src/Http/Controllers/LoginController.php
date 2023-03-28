<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Http\Controllers;

use Exception;
use Illuminate\Contracts\Support\Responsable;
use Jumbojett\OpenIDConnectClientException;
use MinVWS\OpenIDConnectLaravel\Http\Responses\LoginResponseInterface;
use MinVWS\OpenIDConnectLaravel\OpenIDConnectClient;
use MinVWS\OpenIDConnectLaravel\Services\OpenIDConnectExceptionHandlerInterface;

class LoginController extends Controller
{
    public function __construct(
        protected OpenIDConnectClient $client,
        protected OpenIDConnectExceptionHandlerInterface $exceptionHandler,
    ) {
    }

    public function __invoke(): Responsable
    {
        // This redirects to the client and handles the redirect back
        try {
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

        // Return the user information in a response
        return app(LoginResponseInterface::class, ['userInfo' => $userInfo]);
    }
}

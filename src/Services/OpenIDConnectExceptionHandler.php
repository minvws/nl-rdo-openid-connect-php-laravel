<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services;

use Exception;
use Illuminate\Contracts\Support\Responsable;
use Jumbojett\OpenIDConnectClientException;

class OpenIDConnectExceptionHandler implements OpenIDConnectExceptionHandlerInterface
{
    public function handleExceptionWhileAuthenticate(OpenIDConnectClientException $exception): Responsable
    {
        if (str_starts_with($exception->getMessage(), 'Error: ')) {
            return $this->handleRequestError($exception);
        }

        if ($exception->getMessage() === 'Unable to determine state') {
            return $this->handleUnableToDetermineState($exception);
        }

        return $this->defaultResponse($exception);
    }

    /**
     * Called when request to userinfo endpoint fails, jwt signature is invalid, or userinfo is not an object.
     * @param OpenIDConnectClientException $exception
     * @return Responsable
     */
    public function handleExceptionWhileRequestUserInfo(OpenIDConnectClientException $exception): Responsable
    {
        return $this->defaultResponse($exception);
    }

    public function handleException(Exception $exception): Responsable
    {
        return $this->defaultResponseGenericException($exception);
    }

    /**
     * Called when url contains query parameter error.
     * For example user is sent back from idp with error=login_cancelled.
     * @param OpenIDConnectClientException $exception
     * @return Responsable
     */
    protected function handleRequestError(OpenIDConnectClientException $exception): Responsable
    {
        return $this->default400Response($exception);
    }

    /**
     * Called when url contains query parameter code and state, and state does not match with the value from session.
     * @param OpenIDConnectClientException $exception
     * @return Responsable
     */
    protected function handleUnableToDetermineState(OpenIDConnectClientException $exception): Responsable
    {
        return $this->default400Response($exception);
    }

    protected function defaultResponse(OpenIDConnectClientException $exception): Responsable
    {
        abort(500, $exception->getMessage());
    }

    protected function defaultResponseGenericException(Exception $exception): Responsable
    {
        abort(500, $exception->getMessage());
    }

    protected function default400Response(OpenIDConnectClientException $exception): Responsable
    {
        abort(400, $exception->getMessage());
    }
}

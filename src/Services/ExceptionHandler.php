<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Services;

use Exception;
use Jumbojett\OpenIDConnectClientException;
use Symfony\Component\HttpFoundation\Response;

class ExceptionHandler implements ExceptionHandlerInterface
{
    public function handleExceptionWhileAuthenticate(OpenIDConnectClientException $exception): Response
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
     * @return Response
     */
    public function handleExceptionWhileRequestUserInfo(OpenIDConnectClientException $exception): Response
    {
        return $this->defaultResponse($exception);
    }

    public function handleException(Exception $exception): Response
    {
        return $this->defaultResponseGenericException($exception);
    }

    /**
     * Called when url contains query parameter error.
     * For example user is sent back from idp with error=login_cancelled.
     * @param OpenIDConnectClientException $exception
     * @return Response
     */
    protected function handleRequestError(OpenIDConnectClientException $exception): Response
    {
        return $this->default400Response($exception);
    }

    /**
     * Called when url contains query parameter code and state, and state does not match with the value from session.
     * @param OpenIDConnectClientException $exception
     * @return Response
     */
    protected function handleUnableToDetermineState(OpenIDConnectClientException $exception): Response
    {
        return $this->default400Response($exception);
    }

    protected function defaultResponse(OpenIDConnectClientException $exception): Response
    {
        abort(500, $exception->getMessage());
    }

    protected function defaultResponseGenericException(Exception $exception): Response
    {
        abort(500, $exception->getMessage());
    }

    protected function default400Response(OpenIDConnectClientException $exception): Response
    {
        abort(400, $exception->getMessage());
    }
}

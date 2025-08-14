<?php

declare(strict_types=1);

namespace MinVWS\OpenIDConnectLaravel\Tests\Feature;

use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use MinVWS\OpenIDConnectLaravel\OpenIDConnectClient;
use MinVWS\OpenIDConnectLaravel\Tests\TestCase;
use Symfony\Component\HttpFoundation\Response;

class OpenIDConnectClientTest extends TestCase
{
    public function testSignOut(): void
    {
        Http::fake([
            'https://provider.example.com/.well-known/openid-configuration' => Http::response([
                "end_session_endpoint" => "https://provider.example.com/logout",
            ])
        ]);
        Config::set('oidc.issuer', 'https://provider.example.com');
        Config::set('oidc.configuration_cache.store', null);

        $client = app(OpenIDConnectClient::class);

        try {
            $client->signOut('idToken', 'redirect');
        } catch (HttpResponseException $e) {
            $this->assertEquals(Response::HTTP_FOUND, $e->getResponse()->getStatusCode());
            $this->assertEquals(
                'https://provider.example.com/logout?id_token_hint=idToken&post_logout_redirect_uri=redirect',
                $e->getResponse()->getTargetUrl()
            );

            return;
        }
    }
}

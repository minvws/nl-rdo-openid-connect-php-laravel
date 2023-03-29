<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use MinVWS\OpenIDConnectLaravel\Http\Controllers\LoginController;

Route::get(config('oidc.route_configuration.login_route'), LoginController::class)->name('oidc.login');

<?php

namespace Tests;

use App\Services\VibeNestAuth;
use PHPUnit\Framework\TestCase;

final class VibeNestAuthTest extends TestCase
{
    public function testAuthorizationUsesPkceStateAndNonce(): void
    {
        $auth = new VibeNestAuth('https://vibenest.net/', 'client-reference', null, 'https://reference.example/auth/vibenest/callback');
        $flow = $auth->begin(['issuer' => 'https://vibenest.net/', 'authorization_endpoint' => 'https://vibenest.net/oauth/authorize']);
        parse_str(parse_url($flow['url'], PHP_URL_QUERY), $query);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertSame($flow['pending']['state'], $query['state']);
        self::assertSame($flow['pending']['nonce'], $query['nonce']);
        self::assertSame('https://reference.example/auth/vibenest/callback', $query['redirect_uri']);
        self::assertArrayHasKey('verifier', $flow['pending']);
    }

    public function testInsecureIssuerIsRejected(): void
    {
        $this->expectException(\RuntimeException::class);
        new VibeNestAuth('http://vibenest.invalid/', 'client', null, 'https://reference.example/auth/vibenest/callback');
    }
}

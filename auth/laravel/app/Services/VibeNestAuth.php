<?php

namespace App\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use RuntimeException;

final class VibeNestAuth
{
    public function __construct(
        private readonly string $issuer,
        private readonly string $clientId,
        private readonly ?string $clientSecret,
        private readonly string $redirectUri,
    ) {
        if (parse_url($issuer, PHP_URL_SCHEME) !== 'https' || parse_url($redirectUri, PHP_URL_SCHEME) !== 'https') {
            throw new RuntimeException('OIDC issuer and callback must use HTTPS.');
        }
    }

    public static function fromEnvironment(): self
    {
        return new self(
            rtrim(self::required('VIBENEST_AUTH_ISSUER'), '/').'/',
            self::required('VIBENEST_AUTH_CLIENT_ID'),
            env('VIBENEST_AUTH_CLIENT_SECRET') ?: null,
            self::required('VIBENEST_AUTH_REDIRECT_URI'),
        );
    }

    public function begin(array $metadata): array
    {
        $this->assertMetadata($metadata);
        $verifier = self::base64Url(random_bytes(64));
        $pending = [
            'verifier' => $verifier,
            'state' => self::base64Url(random_bytes(32)),
            'nonce' => self::base64Url(random_bytes(32)),
            'expires_at' => time() + 300,
        ];
        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => 'openid profile email',
            'code_challenge' => self::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            'state' => $pending['state'],
            'nonce' => $pending['nonce'],
        ], '', '&', PHP_QUERY_RFC3986);
        return ['url' => $metadata['authorization_endpoint'].'?'.$query, 'pending' => $pending];
    }

    public function complete(array $query, array $pending, array $metadata): array
    {
        $this->assertMetadata($metadata);
        if (($pending['expires_at'] ?? 0) < time()
            || !isset($query['code'], $query['state'], $pending['state'], $pending['verifier'], $pending['nonce'])
            || !hash_equals($pending['state'], $query['state'])) {
            throw new RuntimeException('Invalid or expired OIDC callback.');
        }
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $query['code'],
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $pending['verifier'],
        ];
        if ($this->clientSecret !== null) {
            $form['client_secret'] = $this->clientSecret;
        }
        $token = Http::asForm()->timeout(10)->post($metadata['token_endpoint'], $form)->throw()->json();
        $jwks = Http::timeout(10)->get($metadata['jwks_uri'])->throw()->json();
        JWT::$leeway = 30;
        $claims = (array) JWT::decode($token['id_token'], JWK::parseKeySet($jwks));
        $audience = is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null];
        if (($claims['iss'] ?? null) !== $this->issuer
            || !in_array($this->clientId, $audience, true)
            || !isset($claims['sub'], $claims['exp'], $claims['iat'], $claims['nonce'])
            || !hash_equals($pending['nonce'], (string) $claims['nonce'])) {
            throw new RuntimeException('OIDC ID token validation failed.');
        }
        $profile = [];
        if (isset($token['access_token'], $metadata['userinfo_endpoint'])) {
            $profile = Http::withToken($token['access_token'])->timeout(10)->get($metadata['userinfo_endpoint'])->throw()->json();
            if (($profile['sub'] ?? null) !== $claims['sub']) {
                throw new RuntimeException('UserInfo subject mismatch.');
            }
        }
        return ['subject' => $claims['sub'], 'email' => $profile['email'] ?? $claims['email'] ?? null];
    }

    public function discovery(): array
    {
        $metadata = Http::timeout(10)->get($this->issuer.'.well-known/openid-configuration')->throw()->json();
        $this->assertMetadata($metadata);
        return $metadata;
    }

    public function applicationOrigin(): string
    {
        return parse_url($this->redirectUri, PHP_URL_SCHEME).'://'.parse_url($this->redirectUri, PHP_URL_HOST)
            .(parse_url($this->redirectUri, PHP_URL_PORT) ? ':'.parse_url($this->redirectUri, PHP_URL_PORT) : '');
    }

    private function assertMetadata(array $metadata): void
    {
        if (($metadata['issuer'] ?? null) !== $this->issuer) {
            throw new RuntimeException('OIDC discovery issuer mismatch.');
        }
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function required(string $name): string
    {
        $value = trim((string) env($name, ''));
        if ($value === '') {
            throw new RuntimeException("Missing {$name}.");
        }
        return $value;
    }
}

<?php
declare(strict_types=1);

namespace Asafe2FA;

final class Asafe2FA
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generates a random base32 secret of $length characters (default 32).
     */
    public function generateSecret(int $length = 32): string
    {
        $bytes = random_bytes($length);
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= self::ALPHABET[ord($bytes[$i]) & 31];
        }
        return $out;
    }

    /**
     * Builds an otpauth:// URL compatible with Google Authenticator / Authy.
     */
    public function getOtpAuthUrl(string $account, string $issuer, string $secret): string
    {
        $secret = Base32::normalize($secret);
        $label = $issuer . ':' . $account;

        $params = http_build_query(
            [
                'secret' => $secret,
                'issuer' => $issuer,
            ],
            '',
            '&',
            PHP_QUERY_RFC3986
        );

        return 'otpauth://totp/' . rawurlencode($label) . '?' . $params;
    }

    /**
     * @param array{period?:int,digits?:int,algorithm?:string} $options
     */
    public function getCurrentOtp(string $secret, array $options = []): string
    {
        $period = $options['period'] ?? 30;
        $digits = $options['digits'] ?? 6;
        $algo = $options['algorithm'] ?? 'sha1';
        return Totp::generate($secret, null, $period, $digits, $algo);
    }

    /**
     * @param array{period?:int,digits?:int,algorithm?:string} $options
     */
    public function verifyKey(string $secret, string $token, int $window = 1, array $options = []): bool
    {
        $period = $options['period'] ?? 30;
        $digits = $options['digits'] ?? 6;
        $algo = $options['algorithm'] ?? 'sha1';
        return Totp::verify($token, $secret, $window, $period, $digits, $algo);
    }
}


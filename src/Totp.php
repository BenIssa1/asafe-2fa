<?php
declare(strict_types=1);

namespace Asafe2FA;

final class Totp
{
    /**
     * Generates a TOTP (RFC 6238) from a base32 secret.
     *
     * @param string $secretBase32 Base32 secret
     * @param int|null $timeMs Unix time in milliseconds (default: now)
     * @param int $period step in seconds (default 30)
     * @param int $digits number of digits (default 6)
     * @param string $algo sha1|sha256|sha512 (default sha1)
     */
    public static function generate(
        string $secretBase32,
        ?int $timeMs = null,
        int $period = 30,
        int $digits = 6,
        string $algo = 'sha1'
    ): string {
        $timeMs = $timeMs ?? (int) floor(microtime(true) * 1000);
        $counter = intdiv(intdiv($timeMs, 1000), $period);

        $key = Base32::decode($secretBase32);
        return self::hotp($key, $counter, $digits, $algo);
    }

    public static function verify(
        string $token,
        string $secretBase32,
        int $window = 1,
        int $period = 30,
        int $digits = 6,
        string $algo = 'sha1',
        ?int $timeMs = null
    ): bool {
        $token = preg_replace('/\s+/', '', $token) ?? $token;
        if ($token === '' || preg_match('/^\d+$/', $token) !== 1) return false;

        $timeMs = $timeMs ?? (int) floor(microtime(true) * 1000);
        $periodMs = $period * 1000;

        for ($i = -$window; $i <= $window; $i++) {
            $expected = self::generate($secretBase32, $timeMs + ($i * $periodMs), $period, $digits, $algo);
            if (hash_equals($expected, $token)) return true;
        }
        return false;
    }

    /**
     * @param string $key raw bytes
     */
    private static function hotp(string $key, int $counter, int $digits, string $algo): string
    {
        $msg = self::counterBytes($counter);
        $mac = hash_hmac($algo, $msg, $key, true); // raw bytes

        $offset = ord($mac[strlen($mac) - 1]) & 0x0f;
        $p0 = ord($mac[$offset]) & 0x7f;
        $p1 = ord($mac[$offset + 1]) & 0xff;
        $p2 = ord($mac[$offset + 2]) & 0xff;
        $p3 = ord($mac[$offset + 3]) & 0xff;

        $code = ($p0 << 24) | ($p1 << 16) | ($p2 << 8) | $p3;
        $mod = 10 ** $digits;
        $otp = (string) ($code % $mod);
        return str_pad($otp, $digits, '0', STR_PAD_LEFT);
    }

    private static function counterBytes(int $counter): string
    {
        // 8-byte big-endian unsigned integer
        $hi = ($counter >> 32) & 0xffffffff;
        $lo = $counter & 0xffffffff;
        return pack('N2', $hi, $lo);
    }
}


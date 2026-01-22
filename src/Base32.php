<?php
declare(strict_types=1);

namespace Asafe2FA;

final class Base32
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function normalize(string $input): string
    {
        $s = strtoupper(trim($input));
        $s = preg_replace('/[\s-]+/', '', $s) ?? $s;
        $s = preg_replace('/=+$/', '', $s) ?? $s;
        return $s;
    }

    /**
     * @return string raw bytes
     */
    public static function decode(string $input): string
    {
        $clean = self::normalize($input);
        if ($clean === '') return '';

        $buffer = 0;
        $bits = 0;
        $out = '';

        $len = strlen($clean);
        for ($i = 0; $i < $len; $i++) {
            $ch = $clean[$i];
            $val = strpos(self::ALPHABET, $ch);
            if ($val === false) {
                throw new \InvalidArgumentException('Invalid base32 character');
            }

            $buffer = ($buffer << 5) | $val;
            $bits += 5;

            while ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buffer >> $bits) & 0xff);
            }
        }

        return $out;
    }

    /**
     * @param string $bytes raw bytes
     */
    public static function encode(string $bytes, bool $padding = false): string
    {
        $n = strlen($bytes);
        if ($n === 0) return '';

        $buffer = 0;
        $bits = 0;
        $out = '';

        for ($i = 0; $i < $n; $i++) {
            $buffer = ($buffer << 8) | ord($bytes[$i]);
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::ALPHABET[($buffer >> $bits) & 31];
            }
        }

        if ($bits > 0) {
            $out .= self::ALPHABET[($buffer << (5 - $bits)) & 31];
        }

        if ($padding) {
            while ((strlen($out) % 8) !== 0) $out .= '=';
        }

        return $out;
    }
}


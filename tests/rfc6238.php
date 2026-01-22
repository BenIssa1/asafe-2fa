<?php
declare(strict_types=1);

require __DIR__ . '/../src/Base32.php';
require __DIR__ . '/../src/Totp.php';

use Asafe2FA\Totp;

// RFC test secret (ASCII "12345678901234567890") in base32
$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

$vectors = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
];

$ok = true;
foreach ($vectors as [$t, $expected]) {
    $got = Totp::generate($secret, $t * 1000, 30, 6, 'sha1');
    if ($got !== $expected) {
        $ok = false;
        echo "FAIL time={$t} expected={$expected} got={$got}\n";
    } else {
        echo "OK   time={$t} otp={$got}\n";
    }
}

exit($ok ? 0 : 1);


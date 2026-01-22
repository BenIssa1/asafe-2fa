<?php
declare(strict_types=1);

require __DIR__ . '/src/Base32.php';
require __DIR__ . '/src/Totp.php';
require __DIR__ . '/src/Asafe2FA.php';

use Asafe2FA\Asafe2FA;

$a2fa = new Asafe2FA();

$account = 'alice@example.com';
$issuer = 'Asafe';

$secret = $a2fa->generateSecret();
$url = $a2fa->getOtpAuthUrl($account, $issuer, $secret);

echo "Secret: {$secret}\n";
echo "OTPAuth URL: {$url}\n";

$otp = $a2fa->getCurrentOtp($secret);
echo "Current OTP: {$otp}\n";

$ok = $a2fa->verifyKey($secret, $otp, 1);
echo "Verify (correct secret): " . ($ok ? 'true' : 'false') . "\n";

$wrongSecret = $a2fa->generateSecret();
echo "Wrong secret: {$wrongSecret}\n";
$okWrong = $a2fa->verifyKey($wrongSecret, $otp, 1);
echo "Verify (wrong secret): " . ($okWrong ? 'true' : 'false') . "\n";


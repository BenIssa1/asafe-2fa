# asernum/sdk-client-asafe (PHP)

TOTP (RFC 6238) library for generating and verifying one-time codes, compatible with Asafe and other TOTP-compatible authenticator apps.

## Installation

```bash
composer require asernum/sdk-client-asafe
```

## Usage

### Basic example

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Asafe2FA\Asafe2FA;

$a2fa = new Asafe2FA();

// Generate a secret key (base32)
$secret = $a2fa->generateSecret();

// Create the OTP Auth URL for QR code scanning
$url = $a2fa->getOtpAuthUrl("alice@example.com", "MyCompany", $secret);

// Get the current OTP code
$otp = $a2fa->getCurrentOtp($secret);

// Verify the OTP code
$ok = $a2fa->verifyKey($secret, $otp, 1);
```

### Understanding the `window` parameter

The `window` parameter in `verifyKey()` allows for a small time drift. TOTP codes change every 30 seconds (by default); a clock difference between the server and the user's device can cause verification to fail.

**Behavior:**
- `window = 0`: accepts only the code for the current period
- `window = 1` (default): accepts codes for the current, previous, and next period (±30 seconds)
- `window = 2`: accepts codes over ±2 periods (±60 seconds)

**Example:**

```php
// Strict verification - current code only
$strict = $a2fa->verifyKey($secret, $userInput, 0);

// Default - ±30 second tolerance (recommended)
$normal = $a2fa->verifyKey($secret, $userInput, 1);

// More lenient - ±60 second tolerance
$lenient = $a2fa->verifyKey($secret, $userInput, 2);
```

**When to use which value:**
- `window = 0`: maximum security (but may fail if clocks are out of sync)
- `window = 1`: general use (good balance of security and usability)
- `window = 2` or more: when clocks may be poorly synchronized

## API

### `generateSecret(length?: int): string`
Generates a random secret key encoded in base32.
- `length`: optional. Number of characters (default: 32, ~160 bits)

### `getOtpAuthUrl(account: string, issuer: string, secret: string): string`
Creates an `otpauth://` URL compatible with Asafe and other TOTP apps.
- `account`: user identifier (e.g. email address)
- `issuer`: service name (e.g. "MyCompany")
- `secret`: secret key from `generateSecret()`

### `getCurrentOtp(secret: string, options?: array): string`
Generates the current TOTP code for the given secret.
- `secret`: the secret key
- `options`: optional TOTP configuration (`period`, `digits`, `algorithm`)

### `verifyKey(secret: string, token: string, window?: int, options?: array): bool`
Verifies whether a TOTP token is valid.
- `secret`: the secret key
- `token`: the OTP code to verify (user input)
- `window`: optional. Time tolerance in periods (default: 1). See [Understanding the `window` parameter](#understanding-the-window-parameter) above
- `options`: optional TOTP configuration
- Returns: `true` if the token is valid, `false` otherwise.

## License

MIT

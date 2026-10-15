# KernAuth PHP example

Example for PHP 8.1 or newer with the sodium extension. This file calls validate and checks the Ed25519 signature.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `kernauth.php`.

```
php kernauth_test.php
```

Run from the repository root so the test can read `vectors.json`. Run the example with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```php
$app = new KernAuth(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__KEY_ID__",
    "__PUBLIC_KEY__",
);
```

## Validate

```php
if (!$app->validate($license, $installation)) {
    fwrite(STDERR, $app->message . "\n");
    exit(1);
}
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io

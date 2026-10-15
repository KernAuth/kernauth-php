# KernAuth PHP example

Paste the public app ID, key ID, and public key from Developers into `kernauth.php`. PHP 8.1 or newer with the sodium extension.

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
echo "Status: {$app->entitlement['status']}\n";
echo "Features: {$app->entitlement['features']}\n";
echo "License: {$app->entitlement['license_id']}\n";
echo "Check expires: {$app->entitlement['expires_at']}\n";
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program reads the HWID from the computer. On Windows that is the signed-in user's SID. `KERN_INSTALLATION_ID` overrides that HWID.

## Run

```
php kernauth_test.php
php kernauth.php
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io

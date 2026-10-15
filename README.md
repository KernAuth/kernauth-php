# KernAuth PHP example

Paste the public app ID from Developers into `index.php`. PHP 8.1 or newer, with curl.

## Start

```php
$app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__");
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
php kernauth_test.php
php index.php
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io

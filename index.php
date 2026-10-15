<?php

require __DIR__ . "/kernauth.php";

function kernauth_license_key(): string {
  $fromEnv = getenv("KERN_LICENSE_KEY");
  if (is_string($fromEnv) && trim($fromEnv) !== "") return trim($fromEnv);
  if (defined("STDIN") && stream_isatty(STDIN)) fwrite(STDOUT, "Enter license: ");
  $line = fgets(STDIN);
  return is_string($line) ? trim($line) : "";
}

$app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__");
if (!$app->check(kernauth_license_key())) {
  fwrite(STDOUT, $app->message . "\n");
  exit(1);
}
fwrite(STDOUT, "Status: active\n");
fwrite(STDOUT, $app->expiresAt !== null ? "Expires: {$app->expiresAt}\n" : "Expires: Lifetime\n");

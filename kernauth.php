<?php

const KERN_API = "https://api.kernauth.com";
const KERN_APP_ID = "__PUBLIC_APP_ID__";
const KERN_KEY_ID = "__KEY_ID__";
const KERN_PUBLIC_KEY = "__PUBLIC_KEY__";

final class KernAuth {
  public bool $success = false;
  public string $message = "";
  public ?array $entitlement = null;

  public function __construct(
    public string $api = KERN_API,
    public string $appId = KERN_APP_ID,
    public string $keyId = KERN_KEY_ID,
    public string $publicKey = KERN_PUBLIC_KEY,
  ) {}

  public function validate(string $licenseKey, string $installationId): bool {
    return $this->call("validate", $licenseKey, $installationId, "License is active");
  }

  private function call(string $mode, string $licenseKey, string $installationId, string $okMessage): bool {
    try {
      $this->entitlement = kernauth_request($mode, $licenseKey, $installationId, $this->api, $this->appId, $this->keyId, $this->publicKey);
    } catch (Throwable $error) {
      $this->success = false;
      $this->message = $error->getMessage();
      $this->entitlement = null;
      return false;
    }
    $this->success = true;
    $this->message = $okMessage;
    return true;
  }
}

function kernauth_fields(): array {
  return ["protocol_version", "entitlement_id", "application_id", "license_id", "status",
    "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"];
}

function kernauth_sorted(mixed $value): mixed {
  if (is_object($value)) {
    $vars = get_object_vars($value);
    ksort($vars, SORT_STRING);
    $out = new stdClass();
    foreach ($vars as $key => $item) $out->$key = kernauth_sorted($item);
    return $out;
  }
  if (is_array($value)) return array_map("kernauth_sorted", $value);
  return $value;
}

function kernauth_features(mixed $value): string {
  if (is_string($value)) $value = json_decode($value, false, 512, JSON_THROW_ON_ERROR);
  return json_encode(kernauth_sorted($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}

function kernauth_canonical(array $entitlement): string {
  $lines = [];
  foreach (kernauth_fields() as $name) {
    $value = $name === "features" ? kernauth_features($entitlement[$name]) : (string) $entitlement[$name];
    if (str_contains($value, "\n") || str_contains($value, "\r")) throw new RuntimeException("Invalid entitlement field");
    $lines[] = "$name=$value";
  }
  return implode("\n", $lines) . "\n";
}

function kernauth_b64(?string $value): ?string {
  if (!is_string($value) || !preg_match("/^[A-Za-z0-9+\\/]+={0,2}$/", $value) || strlen($value) % 4 !== 0) return null;
  $raw = base64_decode($value, true);
  return $raw === false ? null : $raw;
}

function kernauth_verify(array $grant, string $nonce, string $app = KERN_APP_ID, string $keyId = KERN_KEY_ID, string $publicKey = KERN_PUBLIC_KEY, ?int $nowMs = null): bool {
  if (!function_exists("sodium_crypto_sign_verify_detached")) return false;
  try {
    $ent = $grant["entitlement"];
    $nowMs ??= (int) round(microtime(true) * 1000);
    $expiryMs = (int) (new DateTimeImmutable($ent["expires_at"]))->format("Uv");
    if ((int) $ent["protocol_version"] !== 1 || $ent["nonce"] !== $nonce || $ent["application_id"] !== $app ||
        $ent["key_id"] !== $keyId || $ent["status"] !== "active" || $expiryMs <= $nowMs) return false;
    $raw = kernauth_b64($publicKey);
    $signature = kernauth_b64($grant["signature"]);
    if ($raw === null || strlen($raw) !== 32 || $signature === null || strlen($signature) !== 64) return false;
    return sodium_crypto_sign_verify_detached($signature, kernauth_canonical($ent), $raw);
  } catch (Throwable) {
    return false;
  }
}

function kernauth_request(string $mode, string $licenseKey, string $installationId, string $api = KERN_API, string $appId = KERN_APP_ID, string $keyId = KERN_KEY_ID, string $publicKey = KERN_PUBLIC_KEY): array {
  $nonce = rtrim(strtr(base64_encode(random_bytes(24)), "+/", "-_"), "=");
  $fingerprint = hash("sha256", "kernauth-device-v1:$installationId");
  $body = json_encode([
    "protocol_version" => 1, "public_app_id" => $appId, "client_version" => "1.0.0",
    "license_key" => $licenseKey, "fingerprint_version" => 1, "device_fingerprint" => $fingerprint,
    "installation_id" => $installationId, "nonce" => $nonce,
  ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
  $context = stream_context_create(["http" => [
    "method" => "POST", "header" => "Content-Type: application/json\r\n", "content" => $body,
    "timeout" => 10, "ignore_errors" => true,
  ]]);
  $raw = file_get_contents("$api/v1/client/$mode", false, $context);
  $status = 0;
  if (isset($http_response_header[0]) && preg_match("/\\s(\\d{3})\\s/", $http_response_header[0], $match)) $status = (int) $match[1];
  if ($raw === false || $status < 200 || $status >= 300) throw new RuntimeException("$mode failed ($status)");
  $grant = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
  if (!kernauth_verify($grant, $nonce, $appId, $keyId, $publicKey)) throw new RuntimeException("Invalid or expired signed entitlement");
  return $grant["entitlement"];
}

function kernauth_license_key(): string {
  $env = getenv("KERN_LICENSE_KEY");
  if (is_string($env) && trim($env) !== "") return trim($env);
  if (stream_isatty(STDIN)) fwrite(STDOUT, "Enter license: ");
  $line = fgets(STDIN);
  return $line === false ? "" : trim($line);
}

function kernauth_installation_id(): string {
  $env = getenv("KERN_INSTALLATION_ID");
  if (is_string($env) && trim($env) !== "") return trim($env);
  if (is_file("kernauth-install")) {
    $saved = trim((string) file_get_contents("kernauth-install"));
    if ($saved !== "") return $saved;
  }
  $created = bin2hex(random_bytes(16));
  if (file_put_contents("kernauth-install", $created . "\n") === false) {
    fwrite(STDERR, "Could not save the installation id\n");
    exit(1);
  }
  return $created;
}

if (PHP_SAPI === "cli" && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
  $app = new KernAuth();
  if (!$app->validate(kernauth_license_key(), kernauth_installation_id())) {
    fwrite(STDERR, $app->message . "\n");
    exit(1);
  }
  $ent = $app->entitlement;
  echo "Status: {$ent['status']}\n";
  echo "Features: ", kernauth_features($ent["features"]), "\n";
  echo "License: {$ent['license_id']}\n";
  echo "Check expires: {$ent['expires_at']}\n";
}

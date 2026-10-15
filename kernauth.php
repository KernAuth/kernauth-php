<?php

function kernauth_check_body(string $appId, string $licenseKey): array {
  return [
    "protocol_version" => 1,
    "public_app_id" => $appId,
    "client_version" => "1.0.0",
    "license_key" => $licenseKey,
  ];
}

function kernauth_api_message(?array $payload, string $fallback): string {
  $message = $payload["error"]["message"] ?? null;
  return is_string($message) && $message !== "" ? $message : $fallback;
}

final class KernAuth {
  public string $message = "";
  public ?string $expiresAt = null;

  public function __construct(public string $api, public string $appId) {}

  public function check(string $licenseKey): bool {
    $handle = curl_init($this->api . "/v1/client/check");
    curl_setopt_array($handle, [
      CURLOPT_POST => true,
      CURLOPT_HTTPHEADER => ["content-type: application/json"],
      CURLOPT_POSTFIELDS => json_encode(kernauth_check_body($this->appId, $licenseKey), JSON_THROW_ON_ERROR),
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT => 10,
    ]);
    $raw = curl_exec($handle);
    $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    $payload = is_string($raw) && $raw !== "" ? json_decode($raw, true) : null;
    if (!is_array($payload) || $status !== 200 || ($payload["valid"] ?? false) !== true) {
      $this->message = kernauth_api_message(is_array($payload) ? $payload : null, "check failed ($status)");
      $this->expiresAt = null;
      return false;
    }
    $this->message = "License is active";
    $this->expiresAt = is_string($payload["expires_at"] ?? null) ? $payload["expires_at"] : null;
    return true;
  }
}

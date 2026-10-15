<?php

require __DIR__ . "/kernauth.php";

$fixture = json_decode(file_get_contents("vectors.json"), true, 512, JSON_THROW_ON_ERROR);
$now = (int) (new DateTimeImmutable("2026-01-01T00:01:00Z"))->format("Uv");
foreach ($fixture["vectors"] as $vector) {
  $ent = $vector["fields"];
  $grant = ["entitlement" => $ent, "signature" => $vector["signature"]];
  if (kernauth_canonical($ent) !== $vector["canonical"]) fail($vector["name"] . " canonical");
  $expiry = (int) (new DateTimeImmutable($ent["expires_at"]))->format("Uv");
  $ok = kernauth_verify($grant, $ent["nonce"], $ent["application_id"], $vector["public_key"], $now);
  $badNonce = kernauth_verify($grant, "wrong", $ent["application_id"], $vector["public_key"], $now);
  $badApp = kernauth_verify($grant, $ent["nonce"], "pub_other_app", $vector["public_key"], $now);
  $badSig = kernauth_verify(["entitlement" => $ent, "signature" => $vector["signature"] . "AA"], $ent["nonce"], $ent["application_id"], $vector["public_key"], $now);
  $expired = kernauth_verify($grant, $ent["nonce"], $ent["application_id"], $vector["public_key"], $expiry);
  $tampered = $ent;
  $tampered["device_id"] = "other";
  $badDevice = kernauth_verify(["entitlement" => $tampered, "signature" => $vector["signature"]], $ent["nonce"], $ent["application_id"], $vector["public_key"], $now);
  $revoked = $ent;
  $revoked["status"] = "revoked";
  $badStatus = kernauth_verify(["entitlement" => $revoked, "signature" => $vector["signature"]], $ent["nonce"], $ent["application_id"], $vector["public_key"], $now);
  if (!$ok || $badNonce || $badApp || $badSig || $expired || $badDevice || $badStatus) fail($vector["name"]);
}
echo "PHP vectors passed\n";

function fail(string $name): void {
  fwrite(STDERR, "PHP vector failed: $name\n");
  exit(1);
}

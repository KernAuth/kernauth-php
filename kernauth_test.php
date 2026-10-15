<?php

require __DIR__ . "/kernauth.php";

$body = kernauth_check_body("pub_harbor_desktop", "KERN-ABCD-EFGH-IJKL-MNOP");
if ($body !== [
  "protocol_version" => 1,
  "public_app_id" => "pub_harbor_desktop",
  "client_version" => "1.0.0",
  "license_key" => "KERN-ABCD-EFGH-IJKL-MNOP",
]) {
  fwrite(STDERR, "PHP check body failed\n");
  exit(1);
}
if (kernauth_api_message(["error" => ["message" => "Update required"]], "no") !== "Update required") {
  fwrite(STDERR, "PHP message failed\n");
  exit(1);
}
if (kernauth_api_message([], "no") !== "no") {
  fwrite(STDERR, "PHP fallback failed\n");
  exit(1);
}
echo "PHP check passed\n";

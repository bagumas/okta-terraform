# saml_app.tf

resource "okta_app_saml" "secure_app" {
  label  = "Secure SAML App"
  status = "ACTIVE"

  sso_url     = "https://example.com/saml/sso"
  recipient   = "https://example.com/saml/sso"
  destination = "https://example.com/saml/sso"
  audience    = "https://example.com/saml/metadata"

  subject_name_id_template = "$${user.userName}"
  subject_name_id_format   = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

  signature_algorithm     = "RSA_SHA256"
  digest_algorithm        = "SHA256"
  response_signed         = true
  honor_force_authn       = false
  authn_context_class_ref = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

  authentication_policy = okta_app_signon_policy.secure_app_policy.id
}

resource "okta_app_signon_policy" "secure_app_policy" {
  name        = "Secure SAML App Sign-On Policy"
  description = "Requires a managed, registered macOS device meeting corporate assurance standards."
}

resource "okta_app_signon_policy_rule" "require_managed_macos" {
  policy_id = okta_app_signon_policy.secure_app_policy.id
  name      = "Require Managed macOS Device"
  priority  = 0

  access = "ALLOW"

  device_is_registered       = true
  device_is_managed          = true
  device_assurances_included = toset([okta_policy_device_assurance_macos.corporate_macos.id])
}

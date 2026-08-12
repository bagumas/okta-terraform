package main

# Guardrail: every okta_policy_rule_signon must require MFA
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "okta_policy_rule_signon"
  action := resource.change.actions[_]
  action != "delete"
  resource.change.after.mfa_required != true
  msg := sprintf(
    "Sign-on rule '%s' does not require MFA (mfa_required must be true).",
    [resource.address]
  )
}

# Guardrail: mfa_lifetime must be set and reasonable (cap at 480 min / 8hr)
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "okta_policy_rule_signon"
  action := resource.change.actions[_]
  action != "delete"
  lifetime := resource.change.after.mfa_lifetime
  lifetime == null
  msg := sprintf(
    "Sign-on rule '%s' must set mfa_lifetime explicitly.",
    [resource.address]
  )
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "okta_policy_rule_signon"
  action := resource.change.actions[_]
  action != "delete"
  lifetime := resource.change.after.mfa_lifetime
  lifetime > 480
  msg := sprintf(
    "Sign-on rule '%s' has mfa_lifetime of %d minutes, exceeding the 480-minute (8hr) cap.",
    [resource.address, lifetime]
  )
}

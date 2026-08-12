package main

app_resource_types := {"okta_app_saml", "okta_app_oauth", "okta_app_bookmark"}

deny contains msg if {
  resource := input.resource_changes[_]
  app_resource_types[resource.type]
  action := resource.change.actions[_]
  action != "delete"
  policy_id := resource.change.after.authentication_policy
  policy_id == null
  msg := sprintf(
    "App '%s' has no authentication_policy set — it will fall back to the org default policy.",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "okta_app_signon_policy_rule"
  action := resource.change.actions[_]
  action != "delete"
  resource.change.after.device_is_managed == true
  resource.change.after.device_is_registered != true
  msg := sprintf(
    "Rule '%s' sets device_is_managed = true but device_is_registered is not also true.",
    [resource.address]
  )
}

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "okta_app_signon_policy_rule"
  action := resource.change.actions[_]
  action != "delete"
  resource.change.after.device_is_managed == true
  assurances := resource.change.after.device_assurances_included
  count(assurances) == 0
  msg := sprintf(
    "Rule '%s' requires a managed device but references no device_assurances_included policies.",
    [resource.address]
  )
}

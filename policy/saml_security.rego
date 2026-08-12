package main

deny contains msg if {
  resource := input.resource_changes[_]
  resource.type == "okta_app_saml"
  action := resource.change.actions[_]
  action != "delete"
  resource.change.after.response_signed != true
  msg := sprintf(
    "SAML app '%s' does not set response_signed = true.",
    [resource.address]
  )
}

approved_group_names := {"Engineering", "HR", "Security"}

warn contains msg if {
  resource := input.resource_changes[_]
  resource.type == "okta_group"
  action := resource.change.actions[_]
  action != "delete"
  name := resource.change.after.name
  not approved_group_names[name]
  msg := sprintf(
    "Group '%s' (%s) is not in the approved group name list — confirm this is intentional.",
    [name, resource.address]
  )
}

# 1. Define the Okta Provider Configuration
#terraform {
#  required_providers {
#    okta = {
#      source  = "okta/okta"
#      version = "~> 4.0"
#    }
#  }
#}

provider "okta" {
  base_url = "okta.com" # Leverages OKTA_ORG_NAME and OKTA_API_TOKEN environment variables
}

# 2. Reference the target group
data "okta_group" "everyone" {
  name = "Everyone"
}

# 3. Create a Global Tenant Session Policy (Universal Support)
resource "okta_policy_signon" "global_mfa_policy" {
  name        = "Global Trial Sign-On Policy"
  description = "Managed via Policy as Code. Enforces constraints at the tenant perimeter."
  status      = "ACTIVE"

  # Assign to our user scope
  groups_included = [data.okta_group.everyone.id]
}

# 4. Add the Rule to enforce the action constraints
resource "okta_policy_rule_signon" "require_mfa_rule" {
  policy_id = okta_policy_signon.global_mfa_policy.id
  name      = "Enforce MFA Verification"
  status    = "ACTIVE"
  priority  = 1

  # Actions triggered when a user logs into Okta
  access       = "ALLOW"
  mfa_required = true
  mfa_prompt   = "SESSION" # Prompts once per new browser session
  mfa_lifetime = 15
}


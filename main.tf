# 1. Define the Okta Provider Configuration
terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0" # Use the latest stable 4.x branch
    }
  }
}

provider "okta" {
  #org_name  = "trial-5667744" # Your trial subdomain
  base_url = "okta.com"
  #api_token = "007n_k7VXTauS0XD8vHqpbwnSaSsJ4jt0HpgMkNxeA"
}


# 2. Fetch or reference an existing user group
data "okta_group" "everyone" {
  name = "Everyone"
}

# 3. Create the App Sign-On Policy Container
resource "okta_app_signon_policy" "mfa_required_policy" {
  name        = "Strict Trial Security Policy"
  description = "Managed via Policy as Code. Enforces MFA for trial resources."
}

# 4. Create a Policy Rule inside the container (FIXED ARGUMENT)
resource "okta_app_signon_policy_rule" "require_mfa_rule" {
  policy_id = okta_app_signon_policy.mfa_required_policy.id
  name      = "Require MFA from Everyone Group"
  priority  = 1
  status    = "ACTIVE"

  # FIX: Changed from user_group_ids_include to groups_included
  groups_included = [data.okta_group.everyone.id]

  access = "ALLOW"

  # Authentication Requirements
  factor_mode                 = "2FA"
  re_authentication_frequency = "PT12H"

  constraints = [
    jsonencode({
      knowledge = {
        types            = ["password"]
        reauthenticateIn = "PT12H"
      }
    })
  ]
}

# 5. Create a Bookmark App AND bind it to the policy directly (FIXED REMOVED RESOURCE)
resource "okta_app_bookmark" "trial_app" {
  label  = "Internal Trial Portal"
  url    = "https://mycompany.com" # Updated test URL
  status = "ACTIVE"

  # FIX: Attach the policy directly here instead of using a separate assignment resource
  authentication_policy = okta_app_signon_policy.mfa_required_policy.id
}

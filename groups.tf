# groups.tf

resource "okta_group" "engineering" {
  name        = "Engineering"
  description = "Engineering team"
}

resource "okta_group" "hr" {
  name        = "HR"
  description = "Human Resources team"
}

resource "okta_group" "security" {
  name        = "Security"
  description = "Security team"
}

resource "okta_app_group_assignment" "engineering_secure_app" {
  app_id   = okta_app_saml.secure_app.id
  group_id = okta_group.engineering.id
}

resource "okta_app_group_assignment" "hr_another_app" {
  app_id   = okta_app_saml.another_app.id
  group_id = okta_group.hr.id
}

resource "okta_app_group_assignment" "security_oauth_app" {
  app_id   = okta_app_oauth.yet_another_app.id
  group_id = okta_group.security.id
}

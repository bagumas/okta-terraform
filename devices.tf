# devices.tf
resource "okta_policy_device_assurance_macos" "corporate_macos" {
  name = "Corporate macOS Standard"

  os_version              = "14.0"
  disk_encryption_type    = toset(["ALL_INTERNAL_VOLUMES"])
  secure_hardware_present = true
  screenlock_type         = toset(["BIOMETRIC", "PASSCODE"])
}

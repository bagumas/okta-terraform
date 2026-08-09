terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
  }
  backend "s3" {
    bucket         = "sam-terraform-state-unique-bucket-name"
    key            = "okta-terraform/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "sam-terraform-locks"
    encrypt        = true
  }
}

provider "okta" {
  base_url = "okta.com"
}

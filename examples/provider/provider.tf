terraform {
  required_providers {
    iboss = {
      source = "nfvcsd/iboss"
    }
  }
}

# Recommended: API key authentication. Supply the key through the
# IBOSS_API_KEY environment variable (for example from your CI secret store)
# rather than writing it in configuration.
provider "iboss" {}

# Optional: pin the account and gateway instead of discovering them.
# provider "iboss" {
#   account_settings_id = 123456
#   gateway_host        = "cn-0000000000-00-example.ibosscloud.com"
# }

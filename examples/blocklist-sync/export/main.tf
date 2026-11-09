# Read-only export of every security group's block list.
# Run through scripts/sync_blocklists.py; it writes the YAML files.
terraform {
  required_version = ">= 1.7.0"
  required_providers {
    iboss = {
      source = "nfvcsd/iboss"
    }
  }
}

# Credentials come from IBOSS_* environment variables.
provider "iboss" {}

data "iboss_security_groups" "all" {}

data "iboss_blocklist" "group" {
  for_each     = { for g in data.iboss_security_groups.all.groups : tostring(g.group_number) => g.group_number }
  group_number = each.value
}

output "blocklists" {
  description = "Every security group with its block list entries."
  value = [
    for g in data.iboss_security_groups.all.groups : {
      group_number = g.group_number
      group_name   = g.name
      entries      = data.iboss_blocklist.group[tostring(g.group_number)].entries
    }
  ]
}

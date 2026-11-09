# Manages iboss URL list entries from YAML files, one per security group:
#
#   Gateway/Block List/<number>. <group>.yaml   -> blocklist.tf
#   Gateway/Allowlist/<number>. <group>.yaml    -> allowlist.tf
#
# Adding an entry to a file adds it in iboss; removing it deletes it in iboss.
# Entries that already exist in iboss are adopted with import blocks, not
# recreated. scripts/sync_lists.py refreshes the files from iboss.
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

# Warns (without blocking) when a file's group was renamed or removed in iboss.
data "iboss_security_groups" "all" {}

locals {
  current_group_labels = [for g in data.iboss_security_groups.all.groups : "${g.group_number}/${g.name}"]
  stale_list_files = concat(
    [for f, l in local.blocklist_files : "Gateway/Block List/${f}" if !contains(local.current_group_labels, "${l.group_number}/${l.group_name}")],
    [for f, l in local.allowlist_files : "Gateway/Allowlist/${f}" if !contains(local.current_group_labels, "${l.group_number}/${l.group_name}")],
  )
}

check "list_groups_match_iboss" {
  assert {
    condition     = length(local.stale_list_files) == 0
    error_message = "These list files no longer match a security group in iboss (renamed or removed): ${join(", ", local.stale_list_files)}. Run scripts/sync_lists.py to refresh them."
  }
}

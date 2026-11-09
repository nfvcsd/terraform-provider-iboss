# Manages iboss block list entries from "Gateway/Block List/*.yaml".
#
# Each file holds one security group's block list (see README.md). Adding an
# entry to a file adds it in iboss; removing it deletes it in iboss. Entries
# that already exist in iboss are adopted with import blocks, not recreated.
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

locals {
  blocklist_dir = "${path.module}/Gateway/Block List"
  blocklist_files = {
    for f in fileset(local.blocklist_dir, "*.yaml") : f => yamldecode(file("${local.blocklist_dir}/${f}"))
  }

  # One element per URL, keyed "<group_number>/<url>" (the resource's import ID).
  # A URL listed twice in one file fails here with "Duplicate object key".
  blocklist_entries = merge({}, [
    for f, bl in local.blocklist_files : {
      for e in coalesce(bl.entries, []) : "${bl.group_number}/${e.url}" => {
        group_number                  = bl.group_number
        url                           = e.url
        note                          = try(e.note, null)
        is_regex                      = try(e.is_regex, null)
        global                        = try(e.global, null)
        apply_keyword_and_safe_search = try(e.apply_keyword_and_safe_search, null)
        direction                     = try(e.direction, null)
        priority                      = try(e.priority, null)
        weight                        = try(e.weight, null)
        start_port                    = try(e.start_port, null)
        end_port                      = try(e.end_port, null)
      }
    }
  ]...)
}

# Current iboss contents, so only entries that already exist are imported.
# Two files for the same group fail here with "Duplicate object key".
data "iboss_blocklist" "live" {
  for_each     = { for f, bl in local.blocklist_files : tostring(bl.group_number) => bl.group_number }
  group_number = each.value
}

import {
  for_each = {
    for k, e in local.blocklist_entries : k => e
    if contains([for x in data.iboss_blocklist.live[tostring(e.group_number)].entries : x.url], e.url)
  }
  to = iboss_blocklist_entry.this[each.key]
  id = each.key
}

resource "iboss_blocklist_entry" "this" {
  for_each = local.blocklist_entries

  group_number                  = each.value.group_number
  url                           = each.value.url
  note                          = each.value.note
  is_regex                      = each.value.is_regex
  global                        = each.value.global
  apply_keyword_and_safe_search = each.value.apply_keyword_and_safe_search
  direction                     = each.value.direction
  priority                      = each.value.priority
  weight                        = each.value.weight
  start_port                    = each.value.start_port
  end_port                      = each.value.end_port
}

# Warns (without blocking) when a file's group was renamed or removed in iboss.
data "iboss_security_groups" "all" {}

locals {
  current_group_labels = [for g in data.iboss_security_groups.all.groups : "${g.group_number}/${g.name}"]
  stale_blocklist_files = [
    for f, bl in local.blocklist_files : f
    if !contains(local.current_group_labels, "${bl.group_number}/${bl.group_name}")
  ]
}

check "blocklist_groups_match_iboss" {
  assert {
    condition     = length(local.stale_blocklist_files) == 0
    error_message = "These block list files no longer match a security group in iboss (renamed or removed): ${join(", ", local.stale_blocklist_files)}. Run scripts/sync_blocklists.py to refresh them."
  }
}

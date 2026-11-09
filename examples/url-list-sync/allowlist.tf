# Entries from "Gateway/Allowlist/*.yaml", one file per security group.
locals {
  allowlist_dir = "${path.module}/Gateway/Allowlist"
  allowlist_files = {
    for f in fileset(local.allowlist_dir, "*.yaml") : f => yamldecode(file("${local.allowlist_dir}/${f}"))
  }

  # One element per URL, keyed "<group_number>/<url>" (the resource's import ID).
  # A URL listed twice in one file fails here with "Duplicate object key".
  allowlist_entries = merge({}, [
    for f, l in local.allowlist_files : {
      for e in coalesce(l.entries, []) : "${l.group_number}/${e.url}" => {
        group_number                  = l.group_number
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
data "iboss_allowlist" "live" {
  for_each     = { for f, l in local.allowlist_files : tostring(l.group_number) => l.group_number }
  group_number = each.value
}

import {
  for_each = {
    for k, e in local.allowlist_entries : k => e
    if contains([for x in data.iboss_allowlist.live[tostring(e.group_number)].entries : x.url], e.url)
  }
  to = iboss_allowlist_entry.this[each.key]
  id = each.key
}

resource "iboss_allowlist_entry" "this" {
  for_each = local.allowlist_entries

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

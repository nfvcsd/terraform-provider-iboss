data "iboss_allowlist_settings" "default" {
  group_number = 1
}

output "default_group_only_allows_allowlist" {
  value = data.iboss_allowlist_settings.default.only_allow_allowlist
}

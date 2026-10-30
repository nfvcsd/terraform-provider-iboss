data "iboss_allowlist" "default" {
  group_number = 1
}

output "default_allowlist_urls" {
  value = [for e in data.iboss_allowlist.default.entries : e.url]
}

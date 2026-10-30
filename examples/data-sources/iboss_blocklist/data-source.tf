data "iboss_blocklist" "default" {
  group_number = 1
}

output "default_blocklist_urls" {
  value = [for e in data.iboss_blocklist.default.entries : e.url]
}

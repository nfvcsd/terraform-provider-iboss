data "iboss_security_groups" "all" {}

# Map of "<number>. <name>" labels, as shown in the iboss console.
output "security_group_labels" {
  value = [for g in data.iboss_security_groups.all.groups : "${g.group_number}. ${g.name}"]
}

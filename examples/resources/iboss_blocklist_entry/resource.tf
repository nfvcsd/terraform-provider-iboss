data "iboss_security_group" "students" {
  name = "Students"
}

resource "iboss_blocklist_entry" "games" {
  group_number = data.iboss_security_group.students.group_number
  url          = "games.example.com"
  note         = "Managed by Terraform"
}

resource "iboss_blocklist_entry" "pattern" {
  group_number = data.iboss_security_group.students.group_number
  url          = ".*\\.unblocked-games\\.example$"
  is_regex     = true
}

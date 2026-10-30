data "iboss_security_group" "students" {
  name = "Students"
}

resource "iboss_allowlist_entry" "learning_platform" {
  group_number = data.iboss_security_group.students.group_number
  url          = "learning.example.org"
  note         = "Managed by Terraform: district learning platform"
}

# Manage several entries from one list.
locals {
  student_allowlist = toset([
    "library.example.org",
    "math-practice.example.com",
  ])
}

resource "iboss_allowlist_entry" "students" {
  for_each     = local.student_allowlist
  group_number = data.iboss_security_group.students.group_number
  url          = each.value
  note         = "Managed by Terraform"
}

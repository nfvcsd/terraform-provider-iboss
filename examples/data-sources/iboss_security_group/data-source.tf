# Look up a group by its exact name...
data "iboss_security_group" "students" {
  name = "Students"
}

# ...or by number.
data "iboss_security_group" "default" {
  group_number = 1
}

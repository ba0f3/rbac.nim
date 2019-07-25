import rbac, tables

var acl = newSimpleAcl()
acl.addRoles("Super Administrator")
acl.addRole("Administrator", @["Super Administrator"])
acl.addRole("Power User", @["Administrator"])
acl.addRoles("User", "Guest")

acl.addSubjects("Public Wifi", "Restricted Wifi", "LAN")

acl.allow("Super Administrator", "connect", "LAN")
acl.deny("Guest", "connect", "Restricted Wifi")

assert acl.isAllowed("Administrator", "connect", "LAN")
assert acl.isAllowed("Guest", "connect", "LAN") == false



echo acl[]
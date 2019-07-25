import rbac

var acl = newSimpleAcl()
acl.addRoles("user", "guest")
acl.addRole("author", @["user"])
acl.addRole("editor", @["author"])
acl.addRole("administrator", @["editor"])

acl.addSubjects("post", "user", "setting")

acl.allow("user", "read", "post")

acl.allow("author", "create", "post")
acl.allow("author", "edit", "post")
acl.allow("author", "delete", "post")

acl.allow("editor", "edit-others", "post")
acl.allow("editor", "delete-others", "post")

acl.allow("administrator", "create", "user")
acl.allow("administrator", "edit", "user")
acl.allow("administrator", "delete", "user")

acl.allow("administrator", "manage", "setting")

acl.deny("guest", "read", "post")

assert acl.isAllowed("administrator", "read", "post")
assert acl.isAllowed("administrator", "create", "post")
assert acl.isAllowed("administrator", "edit", "post")
assert acl.isAllowed("administrator", "delete", "post")
assert acl.isAllowed("administrator", "edit-others", "post")
assert acl.isAllowed("administrator", "delete-others", "post")
assert acl.isAllowed("administrator", "create", "user")
assert acl.isAllowed("administrator", "edit", "user")
assert acl.isAllowed("administrator", "delete", "user")
assert acl.isAllowed("administrator", "manage", "setting")

assert acl.isAllowed("editor", "read", "post")
assert acl.isAllowed("editor", "create", "post")
assert acl.isAllowed("editor", "edit", "post")
assert acl.isAllowed("editor", "delete", "post")
assert acl.isAllowed("editor", "edit-others", "post")
assert acl.isAllowed("editor", "delete-others", "post")
assert acl.isAllowed("editor", "create", "user") == false
assert acl.isAllowed("editor", "edit", "user") == false
assert acl.isAllowed("editor", "delete", "user") == false
assert acl.isAllowed("editor", "manage", "setting") == false

assert acl.isAllowed("author", "read", "post")
assert acl.isAllowed("author", "create", "post")
assert acl.isAllowed("author", "edit", "post")
assert acl.isAllowed("author", "delete", "post")
assert acl.isAllowed("author", "edit-others", "post") == false
assert acl.isAllowed("author", "delete-others", "post") == false
assert acl.isAllowed("author", "create", "user") == false
assert acl.isAllowed("author", "edit", "user") == false
assert acl.isAllowed("author", "delete", "user") == false
assert acl.isAllowed("author", "manage", "setting") == false

assert acl.isAllowed("user", "read", "post")
assert acl.isAllowed("user", "create", "post") == false
assert acl.isAllowed("user", "edit", "post") == false
assert acl.isAllowed("user", "delete", "post") == false
assert acl.isAllowed("user", "edit-others", "post") == false
assert acl.isAllowed("user", "delete-others", "post") == false
assert acl.isAllowed("user", "create", "user") == false
assert acl.isAllowed("user", "edit", "user") == false
assert acl.isAllowed("user", "delete", "user") == false
assert acl.isAllowed("user", "manage", "setting") == false

assert acl.isDenied("guest", "read", "post")
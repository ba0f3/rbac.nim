import rbac

type
  Role = enum
    Guest,
    User,
    Author,
    Editor,
    Administrator

  Subject = enum
    Posts,
    Users,
    Settings

  Permission = enum
    Read,
    Create,
    Edit,
    Delete,
    EditOthers
    DeleteOthers
    Manage


var acl = newAcl[Role, Subject, Permission]()
acl.addRoles(User, Guest)
acl.addRole(Author, @[User])
acl.addRole(Editor, @[Author])
acl.addRole(Administrator, @[Editor])

acl.addSubjects(Posts, Users, Settings)

acl.allow(User, Read, Posts)

acl.allow(Author, Create, Posts)
acl.allow(Author, Edit, Posts)
acl.allow(Author, Delete, Posts)

acl.allow(Editor, EditOthers, Posts)
acl.allow(Editor, DeleteOthers, Posts)

acl.allow(Administrator, Create, Users)
acl.allow(Administrator, Edit, Users)
acl.allow(Administrator, Delete, Users)

acl.allow(Administrator, Manage, Settings)

acl.deny(Guest, Read, Posts)

assert acl.isAllowed(Administrator, Read, Posts)
assert acl.isAllowed(Administrator, Create, Posts)
assert acl.isAllowed(Administrator, Edit, Posts)
assert acl.isAllowed(Administrator, Delete, Posts)
assert acl.isAllowed(Administrator, EditOthers, Posts)
assert acl.isAllowed(Administrator, DeleteOthers, Posts)
assert acl.isAllowed(Administrator, Create, Users)
assert acl.isAllowed(Administrator, Edit, Users)
assert acl.isAllowed(Administrator, Delete, Users)
assert acl.isAllowed(Administrator, Manage, Settings)

assert acl.isAllowed(Editor, Read, Posts)
assert acl.isAllowed(Editor, Create, Posts)
assert acl.isAllowed(Editor, Edit, Posts)
assert acl.isAllowed(Editor, Delete, Posts)
assert acl.isAllowed(Editor, EditOthers, Posts)
assert acl.isAllowed(Editor, DeleteOthers, Posts)
assert acl.isAllowed(Editor, Create, Users) == false
assert acl.isAllowed(Editor, Edit, Users) == false
assert acl.isAllowed(Editor, Delete, Users) == false
assert acl.isAllowed(Editor, Manage, Settings) == false

assert acl.isAllowed(Author, Read, Posts)
assert acl.isAllowed(Author, Create, Posts)
assert acl.isAllowed(Author, Edit, Posts)
assert acl.isAllowed(Author, Delete, Posts)
assert acl.isAllowed(Author, EditOthers, Posts) == false
assert acl.isAllowed(Author, DeleteOthers, Posts) == false
assert acl.isAllowed(Author, Create, Users) == false
assert acl.isAllowed(Author, Edit, Users) == false
assert acl.isAllowed(Author, Delete, Users) == false
assert acl.isAllowed(Author, Manage, Settings) == false

assert acl.isAllowed(User, Read, Posts)
assert acl.isAllowed(User, Create, Posts) == false
assert acl.isAllowed(User, Edit, Posts) == false
assert acl.isAllowed(User, Delete, Posts) == false
assert acl.isAllowed(User, EditOthers, Posts) == false
assert acl.isAllowed(User, DeleteOthers, Posts) == false
assert acl.isAllowed(User, Create, Users) == false
assert acl.isAllowed(User, Edit, Users) == false
assert acl.isAllowed(User, Delete, Users) == false
assert acl.isAllowed(User, Manage, Settings) == false

assert acl.isDenied(Guest, Read, Posts)
# RABC
Simple Role-based Access Control library


### Usage

```nim
import rbac

type
  Role = enum
    Guest, User, Author, Editor, Administrator

  Subject = enum
    Posts, Users, Settings

  Permission = enum
    Read, Create, Edit, Delete, EditOthers, DeleteOthers, Manage


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

assert acl.isDenied(Guest, Read, Posts)
```

Please find in [tests](tree/master/tests) folder for more examples
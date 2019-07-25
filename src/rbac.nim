import tables

type
  RoleNotFoundException = object of Exception
  SubjectNotFoundException = object of Exception

  ACL[R, S, P] = ref object of RootObj
    children: Table[R, seq[R]]
    roles: Table[R, seq[R]]
    subjects: Table[S, seq[S]]

    allowed: seq[tuple[role: R, perm: P, subject: S]]
    denied: seq[tuple[role: R, perm: P, subject: S]]

proc getChildren[R](acl: ACL, role: R): seq[R] =
  if acl.children.hasKey(role):
    result.add(acl.children[role])
    for r in acl.children[role]:
      result.add(acl.getChildren(r))


proc addRoles*[R](acl: ACL, roles: varargs[R]) =
  for role in roles:
    acl.roles[role] = @[]

proc addRole*[R](acl: ACL, role: R, parents: seq[R]) =
  acl.roles[role] = parents
  for parent in parents:
    if parent notin acl.roles:
      raise newException(RoleNotFoundException, "role '" & $parent & "' is not defined yet")
    if parent notin acl.children:
      acl.children[parent] = @[role]
    else:
      acl.children[parent].add(role)

proc addSubjects*[S](acl: ACL, subjects: varargs[S]) =
  for subject in subjects:
    acl.subjects[subject] = @[]

proc addSubject*[S](acl: ACL, subject: S, parents: seq[S]) =
  acl.subjects[subject] = parents

proc allow*[R, S, P](acl: ACL, role: R, permission: P, subject: S, includeChildren = true) =
  if not acl.roles.hasKey(role):
    raise newException(RoleNotFoundException, "role '" & $role & "' is not defined yet")

  if not acl.subjects.hasKey(subject):
    raise newException(SubjectNotFoundException, "subject '" & $subject & "' is not defined yet")

  var rule: tuple[role: R, perm: P, subject: S]
  if includeChildren:
    for r in acl.getChildren(role):
      rule = (r, permission, subject)
      if rule notin acl.allowed:
        acl.allowed.add(rule)
  rule = (role, permission, subject)
  if rule notin acl.allowed:
    acl.allowed.add(rule)

proc deny*[R, S, P](acl: ACL, role: R, permission: P, subject: S, includeChildren = true) =
  if not acl.roles.hasKey(role):
    raise newException(RoleNotFoundException, "role '" & $role & "' is not defined yet")

  if not acl.subjects.hasKey(subject):
    raise newException(SubjectNotFoundException, "subject '" & $subject & "' is not defined yet")

  var rule: tuple[role: R, perm: P, subject: S]
  if includeChildren:
    for r in acl.getChildren(role):
      rule = (r, permission, subject)
      if rule notin acl.allowed:
        acl.denied.add(rule)
  rule = (role, permission, subject)
  if rule notin acl.allowed:
    acl.denied.add(rule)

proc isAllowed*[R, S, P](acl: ACL, role: R, permission: P, subject: S): bool =
  (role, permission, subject) in acl.allowed

proc isDenied*[R, S, P](acl: ACL, role: R, permission: P, subject: S): bool =
  (role, permission, subject) in acl.denied



proc newSimpleAcl*(): ACL[string, string, string] =
  result = new ACL[string, string, string]

proc newAcl*[R, S, P](): ACL[R, S, P] =
  result = new ACL[R, S, P]

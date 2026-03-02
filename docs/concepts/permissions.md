# Permissions, Groups, and ACLs

## What Are Permissions?

Imagine you have a diary. You probably don't want everyone to be able to read it, right? And you _definitely_ don't want anyone else writing in it!

That's exactly what **file permissions** do in an operating system. Every file has rules about who can:

- **Read** it (look at what's inside)
- **Write** to it (change what's inside)
- **Execute** it (run it as a program)

## Owner, Group, and Others

Every file has three levels of access, like three circles around it:

```
 ┌──────────────────────────────┐
 │         Others (o)           │
 │   ┌──────────────────────┐   │
 │   │      Group (g)       │   │
 │   │   ┌──────────────┐   │   │
 │   │   │  Owner (u)   │   │   │
 │   │   └──────────────┘   │   │
 │   └──────────────────────┘   │
 └──────────────────────────────┘
```

- **Owner** — the person who created the file. They usually get full control.
- **Group** — a set of users who share access. Think of a school club: everyone in the Art Club can use the art supplies.
- **Others** — everyone else on the system.

Each level gets its own read, write, and execute flags. We write them as a 9-character string:

```
rwxr-xr--
│││││││││
│││││││└┘── Others:  r-- (read only)
│││││└┘──── Group:   r-x (read + execute)
│││└┘────── Owner:   rwx (read + write + execute)
```

## Groups — Like School Clubs

A **group** is a named collection of users. Just like how your school might have a Robotics Club and a Drama Club, an OS can have groups like `devs` (developers) or `admins` (administrators).

The cool thing is that one person can be in multiple groups, just like you might be in both the Robotics Club and the Chess Club.

When a file belongs to a group, every member of that group gets the group's permissions. So if the `devs` group has read access to a config file, every developer can read it.

### Try it in PyOS

```
groups add devs          # Create a group called "devs"
adduser alice            # Create a user
groups adduser 1 1       # Add alice (uid 1) to devs (gid 1)
groups list              # See all groups and members
groups                   # See your current groups
```

## The Execute Bit — Like a Key to Start a Machine

Reading a file is like looking at a recipe card. Writing to a file is like changing the recipe. But **executing** a file is like actually _cooking_ the recipe — turning it into something that runs.

Not every file should be executable. A text document? No need to run that. But a program? That needs the execute bit turned on, like a key that unlocks the ability to run it.

Without the execute bit, a file is just data sitting there. With it, the file becomes something the computer can actually run as a program.

### Try it in PyOS

```
touch /myprogram                         # Create a file
chmod /myprogram rwxr-xr-x               # Owner, group, and others can execute
chmod /myprogram rw-r--r--               # Nobody can execute (just read/write)
```

## ACLs — The Detailed Guest List

Regular permissions (owner/group/others) are like a simple rule: "members only" or "everyone welcome." But sometimes you need more control.

**Access Control Lists (ACLs)** are like a detailed guest list at a party:

- "Alice can come in and eat cake" (specific user, read + write)
- "Everyone in the Chess Club can watch" (specific group, read only)
- "Bob is _not_ allowed, even though he's in the Chess Club" (user override)

ACLs let you set permissions for _specific_ users or groups, without changing the general rules. They take priority over the regular permissions:

1. **User ACL** — checked first (most specific)
2. **Group ACL** — checked next
3. **Owner permissions** — if you're the owner
4. **Group permissions** — if you're in the file's group
5. **Other permissions** — everyone else

And the **root** user (uid 0)? They always get in, no matter what. Root is like the school principal — every door is open.

### Try it in PyOS

```
touch /secret.txt                        # Create a file
setfacl /secret.txt user:1:rwx           # Give alice (uid 1) full access
setfacl /secret.txt group:2:r--          # Give group 2 read-only
getfacl /secret.txt                      # See all permissions + ACLs
```

## Real-World Connection

Every operating system uses permissions:

- **Linux/macOS** use exactly this model: `rwxrwxrwx` plus ACLs
- **Windows** uses a similar system called NTFS permissions
- **Phone apps** ask for permissions too — camera, microphone, contacts

The idea is the same everywhere: **decide who can do what, and enforce it**.

## Shell Commands

| Command | What it does |
|---------|-------------|
| `chmod path rwxrwxrwx` | Set the 9-bit permissions on a file |
| `chown path uid [gid]` | Change who owns a file (and its group) |
| `getfacl path` | Show all permissions and ACL entries |
| `setfacl path type:id:rwx` | Add an ACL entry for a user or group |
| `groups` | Show your current group memberships |
| `groups list` | List all groups |
| `groups add name` | Create a new group |
| `groups adduser uid gid` | Add a user to a group |
| `groups removeuser uid gid` | Remove a user from a group |

## Where to Go Next

- [Users and Safety](users-and-safety.md) -- Users, signals, logging, and deadlocks
- [Filesystem](filesystem.md) -- How files and directories are organised
- [The Shell](shell.md) -- The `chmod`, `chown`, and `groups` commands

## Key Terms

| Term | Definition |
|------|-----------|
| **Permission bits** | Nine flags (rwxrwxrwx) that control who can read, write, and execute a file |
| **Owner** | The user who created the file -- they get the first set of permission bits |
| **Group** | A named collection of users who share the middle set of permission bits |
| **Other** | Everyone else on the system -- they get the last set of permission bits |
| **UID** | User Identifier -- a unique number for each user (root is always 0) |
| **GID** | Group Identifier -- a unique number for each group |
| **ACL** | Access Control List -- extra fine-grained entries beyond the basic 9 bits |
| **root** | The superuser (UID 0) who can bypass all permission checks |

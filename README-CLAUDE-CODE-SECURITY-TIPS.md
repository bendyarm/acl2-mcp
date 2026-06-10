# Tips to Limit Claude Code's Access

References:
- [Permissions](https://code.claude.com/docs/en/permissions)
- [Bash sandbox](https://code.claude.com/docs/en/sandboxing)

Both can be configured in `~/.claude/settings.json`, which contains a JSON object, to which one can add two members:
```
{
    ...

    "premissions": ...

    "sandbox": ...

    ...

}
```


## Permissions


### File System

Permissions control what Claude Code itself can do in terms of access to files and other resources.

There are 'deny', 'ask', and 'allow' permissions. They are evaluated in that order, so one cannot deny access to `/` and allow access to specific subdirectories: one has to deny access to all the subdirectories of interest.

Example:
```
    "permissions": {

        "deny": [

            "Edit(//Library/**)",
            "Write(//Library/**)",

            "Edit(//System/**)",
            "Write(//System/**)",

            "Edit(//usr/**)",
            "Write(//usr/**)",

            "Read(~/.ssh/**)",
            "Edit(~/.ssh/**)",
            "Write(~/.ssh/**)",

            "Read(~/Library/**)",
            "Edit(~/Library/**)",
            "Write(~/Library/**)",

            "Read(~/Pictures/**)",
            "Edit(~/Pictures/**)",
            "Write(~/Pictures/**)",

            "Read(~/Work/funding/**)",
            "Edit(~/Work/funding/**)",
            "Write(~/Work/funding/**)",

            ...

        ]

    }

```

It wants a double slash for the root. The above prevents access to some root-level directories and to some user-home-level directories. The double star means the whole subtree.

macOS may enforce additional restrictions, e.g. about creating a new directory under `/`, which would likely require `sudo`.

Other than explicit deny/ask/allow permissions, Claude Code should be able to read anything not denied (although it probably wouldn't do that) and to edit/write anything in the working directory (i.e. the one in which Claude Code is started). Actually, the latter needs the following:
```
    "permissions": {

        "defaultMode": "acceptEdits",

        ...
    }
```


### Commands

Besides 'read', 'edit', and 'write' permissions on directories, there are other kinds on permissions, e.g. on shell commands, to deny/ask/allow certain patterns of commands.

Example:
```
    "permissions": {

        "deny": [

            "Bash(git commit *)",

            ...

        ]

    }
```

It prevents git commits. It's called `Bash` but it applies to any kind of shell, not just `bash` shells.


### More

See the first link at the beginning for more information on permissions.


## Bash Sandboxing

The bash sandbox controls what can be accessed by processeses started by Claude Code. It uses a process-level sandboxing mechanism in macOS called 'Seatbelt'. The 'bash' does not mean that it is restricted to the `bash` shell; it applies to every kind of shell.

The bash sanbox can be activated and configured via the `/sandbox` command in the CLI, or better in the settings, so it applied to every session:
```
    "sandbox": {

        "enabled": true,

        "autoAllowBashIfSandboxed": true,

        "allowUnsandboxedCommands": true,

        ...
    }
```

By default, with the bash sandbox on, Claude Code can only write the working directory but can read the whole file system; more precisely, not Claude Code itself, but processes started by Claude Code (otherwise for Claude Code itself permissions apply). Since this may involve running commands, perhaps it is best to allow access to `/`, and then deny/allow access to subdirectories as needed. Unlike permissions, deny does not take precedence; so for example one can deny read (which implies write) to the home directory, and only allow read/write to specific subdirectories.

Example:
```
    "sandbox": {

        ...

        "filesystem": {

            "denyRead": ["~/"],
            "allowRead": [".",
                          "~/.gitconfig",
                          "~/.gitignore_global",
                          ...
                          "~/Work/acl2/0",
                          "~/Work/acl2/1",
                          "~/Work/acl2/2",
                          "~/Work/acl2/3",
                          "~/Work/acl2/4",
                          "~/Work/acl2/5",
                          "~/Work/acl2/6",
                          "~/Work/acl2/7",
                          "~/Work/acl2/8"],

            "allowWrite": ["/tmp/claude"]

        }

    }
```

In the above, the `~/Work/acl2/<n>` directories are working directories for Claude Code, each of which contains a clone of the acl2 repo (one level down, e.g. `.../0/<acl2-repo>`), plus other files/directories, like a `CLAUDE.md`, or some working files outside the repository. The access to `.gitconfig` and `.gitignore_global` may be needed to get certain things to work, also with help configuring this from Claude Code itself. The `.` is the current directory, apparently needed there. The write access to `/tmp/claude` may be also needed for certain things to work.

The syntax is more standard here. No double slash, and no double star, unlike permissions.

See the second link first link at the beginning for more information on bash sandboxing.


## Asking Claude Code

Claude Code can also help with these configurations, pointing to documentation, exemplifying things, and diagnosing problems. In one case, it correctly diagnosed that the certification of some ACL2 files using OSICAT needed the addition of the `lib/sbcl/` directory in the user's home to the `allowRead` under `filesystem` under `sandbox` in the settings file.

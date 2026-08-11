# Tips to Limit Codex's Access

## Permissions vs. Sandboxing

Codex provides an older sandboxing mechanism and a newer permissions mechanism. These are incompatible; one should use either one or the other. The permission mechanism is the one to use. The sandboxing mechanism may go away at some point.

Permissions use some OS-level sandboxing, but that is not the same as Codex's sandboxing mechanism.

## Permissions

Reference: [Permissions](https://learn.chatgpt.com/docs/permissions)

Permissions are configured in the file `~/.codex/config.toml`.

One can define _profiles_, each with its own permissions, that can be used in different circumstances. There are some predefined profiles, but it is better to define a custom one.

Here is how to conservatively configure permissions so that Codex only has access to the working directory (workspace) and selectively to explicitly listed files and directories:
```toml
default_permissions = "workspace-only"

[permissions.workspace-only]
extends = ":workspace"

[permissions.workspace-only.filesystem]
":root" = "deny" # Deny the entire filesystem by default.
":minimal" = "read" # Permit only the minimal runtime paths needed for common tools such as shells, /usr/bin, libraries, etc.
":tmpdir" = "deny" # Optional: don't expose temporary directories either.
":slash_tmp" = "deny" # Optional: don't expose temporary directories either.
"/Users/me/.../bin/certone" = "read"
"/Users/me/.../bin/certree" = "read"
"/System/Library/Perl/5.34" = "read"

[permissions.workspace-only.filesystem.":workspace_roots"]
"." = "write" # Current Codex workspace: read + write.

[permissions.workspace-only.network]
enabled = false
```

The `default_permission` line sets the default permission profile to be `workspace-only`. This is just a name; any other name `<name>` would work, but the section name in square brackets must use that name:
```toml
default_permissions = "<name>"

[permissions.<name>]
...

[permissions.<name>.filesystem]
...

[permissions.<name>.filesystem.":workspace_roots"]
...

[permissions.<name>.network]
...
```

The `config.toml` file may have other unrelated content. It is critical that the `default_permissions` line come before any section `[...]` (not just permission sections; all sections); otherwise the `default_permissions` is interpreted as a field of the closest preceding section.

The `extends` line says that our custom `workspace-only` profile extends the predefined `:workspace` profile, which, despite what is suggested by its similarity with the name of our custom profile, is not exactly what we want, i.e. we need additional permission configurations.

The first four lines under `[permissions.workspace-only.filesystem]` carry explanatory comments. The other three lines are custom additions to let Codex certify ACL2 files; the scripts `certone` for single files and `certree` for directory trees, and the Perl directory.

The part with `:workspace_roots` gives Codex free rein in the working directory, i.e. where the Codex CLI is started. More entries can be added here.

The last part disables network access.

## Approvals

Reference: [Approvals](https://learn.chatgpt.com/docs/agent-approvals-security)

Add the following to the `config.toml` file, also before any `[...]` part:
```toml
approval_policy = { granular = {
    sandbox_approval = false,
    request_permissions = false,
    rules = true,
    mcp_elicitations = true,
    skill_approval = true
} }
```

The two lines with `false` mean that Codex will never even try to ask to violate the sandbox or permission approvals. Probably the one about sandboxing is irrelevant, if one uses permissions instead of sandboxing. The three lines with `true` allow Codex to ask approvals in other cases.

## More Information

The above setup seems to be working well for doing ACL2 work, but it has not been extensively tested. It is possible that some settings are too strict.

Besides the Codex documentation, one can ask the AI itself information on how to configure these things.

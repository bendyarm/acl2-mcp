# Security

This document describes the security measures implemented in the ACL2 MCP server.

## Security Model

The ACL2 MCP server executes arbitrary ACL2 code provided by the client. This is inherently powerful and requires careful security considerations. The server is designed to be run locally by a trusted user (e.g., as part of Claude Code) and assumes the client has permission to execute ACL2 code on the system.

## Threat Model

**In Scope:**
- Command injection attacks through malicious inputs
- Path traversal attacks accessing unauthorized files
- Resource exhaustion through unbounded inputs
- Information disclosure through error messages

**Out of Scope:**
- Network-based attacks (server runs locally via stdio)
- Multi-tenancy and isolation (single-user design)
- ACL2 itself (we trust ACL2's security model)

## Security Measures

### 1. Input Validation

**ACL2 Identifiers** (`validate_acl2_identifier`):
- Rejects identifiers containing quotes (`"`, `'`)
- Rejects identifiers containing parentheses (`(`, `)`)
- Prevents code injection through function/theorem names

**Timeout Values** (`validate_timeout`):
- Clamps to range: 1-300 seconds
- Prevents negative or extreme values
- Handles invalid types gracefully

**Code Length**:
- Maximum 1MB of code per request
- Prevents resource exhaustion

### 2. String Escaping

**File Paths** (`escape_acl2_string`):
- Escapes backslashes and quotes in file paths
- Prevents breaking out of ACL2 string literals
- Applied to all file paths passed to ACL2

### 3. File Path Validation

**Path Validation** (`validate_file_path`):
- Resolves to absolute paths
- Verifies file exists
- Verifies path is a file (not a directory)
- Error messages only expose filename, not full path

**Current Limitations:**
- Does not restrict access to specific directories
- Allows reading any file the process can access
- Suitable for local single-user usage only

### 4. Process Isolation

- ACL2 runs as separate subprocess
- Timeout enforcement with process termination
- Temporary files cleaned up after execution
- stdin/stdout/stderr properly captured

### 5. Error Handling

- Generic error messages to avoid information disclosure
- No stack traces exposed to client
- File paths in errors show basename only

## Tested Attack Vectors

The following attack vectors have been tested and mitigated:

1. **Code Injection via Identifiers**: `name='append")(+ 1 1)'`
2. **Code Injection via Paths**: `path='test")(malicious-code)'`
3. **Resource Exhaustion**: 2MB code, 1000 second timeout
4. **Path Traversal**: Non-existent files, directories

See `tests/test_security.py` for complete test coverage.

## Best Practices for Deployment

1. **Run Locally Only**: Never expose this server over a network
2. **Trusted Clients**: Only allow trusted clients (e.g., Claude Code)
3. **File Permissions**: Run with minimal necessary file access
4. **Monitor Resources**: Watch for excessive CPU/memory usage
5. **Update Regularly**: Keep ACL2 and Python dependencies updated

## Reporting Security Issues

If you discover a security vulnerability, please report it by opening an issue on GitHub with the "security" label. Do not publicly disclose the vulnerability until it has been addressed.

## Security Checklist for Code Review

When reviewing changes to this codebase, verify:

- [ ] All user inputs are validated before use
- [ ] File paths are validated with `validate_file_path()`
- [ ] ACL2 identifiers are validated with `validate_acl2_identifier()`
- [ ] Strings interpolated into ACL2 code are escaped with `escape_acl2_string()`
- [ ] Timeouts are validated with `validate_timeout()`
- [ ] No direct string interpolation of user input into ACL2 commands
- [ ] Error messages don't leak sensitive information
- [ ] New functionality has corresponding security tests

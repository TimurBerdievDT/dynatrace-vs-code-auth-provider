# Dynatrace VS Code Base Login

This extension owns the shared authentication provider `dynatrace.debugger.oauth2`.

## Contract

- Provider ID: `dynatrace.debugger.oauth2`
- Shared via VS Code Authentication API (`vscode.authentication.getSession`)
- Exposes command `dynatrace.baseLogin.logout` to remove the active session

Consumer extensions should depend on `Dynatrace.dt-vscode-base-login` and request sessions with matching scopes.

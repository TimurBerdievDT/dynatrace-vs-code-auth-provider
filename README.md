# Dynatrace VS Code Auth Provider

This extension owns the shared authentication provider `dynatrace.authentication`.

## Contract

- Provider ID: `dynatrace.authentication`
- Shared via VS Code Authentication API (`vscode.authentication.getSession`)
- Exposes commands `dynatrace.login` and `dynatrace.logout` for authentication control

Consumer extensions should depend on `Dynatrace.dynatrace-vs-code-auth-provider` and request sessions with matching scopes.

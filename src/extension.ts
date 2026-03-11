import * as vscode from 'vscode'
import { DynatraceLoginAuthProvider } from './authProvider'

const DEFAULT_LOGIN_URL = 'https://sso.dynatrace.com/oauth2/authorize'
const DEFAULT_TOKEN_URL = 'https://token.dynatrace.com/sso/oauth2/token'
const DEFAULT_CLIENT_ID = 'dt0s12.live-debugging-prod'

const getConfigValue = (key: string, fallback: string): string => {
  const value = process.env[key]
  if (!value) {
    return fallback
  }

  return value
}

export const activate = (context: vscode.ExtensionContext): void => {
  const provider = new DynatraceLoginAuthProvider(context, {
    loginUrl: getConfigValue('DT_LOGIN_URL', DEFAULT_LOGIN_URL),
    tokenValidator: getConfigValue('DT_TOKEN_URL', DEFAULT_TOKEN_URL),
    clientId: getConfigValue('DT_CLIENT_ID', DEFAULT_CLIENT_ID)
  })

  context.subscriptions.push(provider)

  // Create status bar item for quick access
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100)
  statusBar.name = 'Dynatrace Login Status'
  context.subscriptions.push(statusBar)

  // Update status bar based on session state
  const updateStatusBar = async (): Promise<void> => {
    const sessions = await provider.getSessions()
    const isLoggedIn = sessions.length > 0
    
    // Update VS Code context for conditional keybindings
    await vscode.commands.executeCommand('setContext', 'dynatrace.isLoggedIn', isLoggedIn)
    
    if (isLoggedIn) {
      const email = sessions[0].account.label || sessions[0].account.id
      statusBar.text = `$(account) Dynatrace: ${email}`
      statusBar.tooltip = 'Click to log out'
      statusBar.command = 'dynatrace.logout'
    } else {
      statusBar.text = '$(sign-in) Dynatrace: Sign In'
      statusBar.tooltip = 'Click to log in'
      statusBar.command = 'dynatrace.login'
    }
    statusBar.show()
  }

  // Listen to session changes and update status bar
  context.subscriptions.push(
    provider.onDidChangeSessions(async () => {
      await updateStatusBar()
    })
  )

  // Register logout command
  context.subscriptions.push(
    vscode.commands.registerCommand('dynatrace.logout', async () => {
      const sessions = await provider.getSessions()
      const activeSession = sessions[0]
      if (!activeSession) {
        return
      }
      await provider.removeSession(activeSession.id)
    })
  )

  // Register login command
  context.subscriptions.push(
    vscode.commands.registerCommand('dynatrace.login', async () => {
      await vscode.authentication.getSession('dynatrace.authentication', [], { createIfNone: true })
      await updateStatusBar()
    })
  )

  // Initialize status bar
  void updateStatusBar()
}

export const deactivate = (): void => undefined

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
  context.subscriptions.push(
    vscode.commands.registerCommand('dynatrace.baseLogin.logout', async () => {
      const sessions = await provider.getSessions()
      const activeSession = sessions[0]
      if (!activeSession) {
        return
      }
      await provider.removeSession(activeSession.id)
    })
  )
}

export const deactivate = (): void => undefined

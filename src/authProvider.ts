import {
  authentication,
  AuthenticationGetSessionOptions,
  AuthenticationProvider,
  AuthenticationProviderAuthenticationSessionsChangeEvent,
  AuthenticationSession,
  Disposable,
  env,
  Event,
  EventEmitter,
  ExtensionContext,
  ProgressLocation,
  Uri,
  window
} from 'vscode'
import crypto from 'crypto'
import { AuthServer } from './authServer'
import { generateOAuthChallengeAndVerifier } from './oauth2Utils'
import { AuthResponse, OAuthSession } from './types'

interface JwtPayloadLike {
  exp?: number
  email?: string
}

const AUTH_PORT = 3232
const AUTH_PATH = '/auth/login'
const OAUTH_SECRETS_PREFIX = 'dynatrace.authentication'
export const SESSIONS_SECRET_KEY = `${OAUTH_SECRETS_PREFIX}.sessions`
const REFRESH_TOKEN_SECRET_KEY = `${OAUTH_SECRETS_PREFIX}.refresh.token`
export const AUTH_IDENTIFIER = 'dynatrace.authentication'
const AUTH_TITLE = 'Dynatrace SSO'

type AuthSessionChangeReason = 'added' | 'changed'

export type AuthConfig = {
  loginUrl: string
  clientId: string
  tokenValidator: string
}

export class DynatraceLoginAuthProvider implements AuthenticationProvider, Disposable {
  private readonly sessionChangeEmitter = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>()
  private readonly disposable: Disposable
  private initializedDisposable: Disposable | undefined
  private currentSession: AuthenticationSession | undefined

  public constructor(
    private readonly context: ExtensionContext,
    private readonly config: AuthConfig
  ) {
    this.context.subscriptions.push(this.sessionChangeEmitter)
    this.disposable = Disposable.from(
      authentication.registerAuthenticationProvider(AUTH_IDENTIFIER, AUTH_TITLE, this, {
        supportsMultipleAccounts: false
      })
    )
  }

  public get onDidChangeSessions(): Event<AuthenticationProviderAuthenticationSessionsChangeEvent> {
    return this.sessionChangeEmitter.event
  }

  public async getSessions(
    _scopes?: readonly string[],
    _options?: AuthenticationGetSessionOptions
  ): Promise<AuthenticationSession[]> {
    void _scopes
    void _options
    this.ensureInitialized()
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY)
    if (!allSessions) {
      this.currentSession = undefined
      return []
    }

    const sessions = JSON.parse(allSessions) as AuthenticationSession[]
    if (sessions.length === 0) {
      this.currentSession = undefined
      return sessions
    }

    const refreshed = await this.tryRefreshIfNeeded(sessions[0])
    const activeSessions = refreshed ? [refreshed] : sessions
    this.currentSession = activeSessions[0]
    return activeSessions
  }

  public async createSession(scopes: readonly string[]): Promise<AuthenticationSession> {
    this.ensureInitialized()
    const tokens = await this.login(scopes)
    return this.assignSession(tokens, 'added')
  }

  public async removeSession(sessionId: string): Promise<void> {
    this.ensureInitialized()
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY)
    if (allSessions) {
      const sessions = JSON.parse(allSessions) as AuthenticationSession[]
      const removedSessions = sessions.filter((session) => session.id === sessionId)
      if (removedSessions.length === 0) {
        return
      }
      this.sessionChangeEmitter.fire({ added: [], removed: removedSessions, changed: [] })
    }

    this.currentSession = undefined
    await this.context.secrets.delete(SESSIONS_SECRET_KEY)
    await this.context.secrets.delete(REFRESH_TOKEN_SECRET_KEY)
  }

  public async dispose(): Promise<void> {
    this.initializedDisposable?.dispose()
    await this.disposable.dispose()
  }

  private ensureInitialized(): void {
    if (this.initializedDisposable) {
      return
    }

    this.initializedDisposable = Disposable.from(
      this.context.secrets.onDidChange((event) => {
        if (event.key === SESSIONS_SECRET_KEY) {
          void this.checkForUpdates()
        }
      }),
      authentication.onDidChangeSessions((event) => {
        if (event.provider.id === AUTH_IDENTIFIER) {
          void this.checkForUpdates()
        }
      })
    )
  }

  private async checkForUpdates(): Promise<void> {
    const previousSession = this.currentSession
    const sessions = await this.getStoredSessions()
    const currentSession = sessions[0]

    if (currentSession?.accessToken === previousSession?.accessToken) {
      return
    }

    const removed = previousSession && !currentSession ? [previousSession] : []
    const added = !previousSession && currentSession ? [currentSession] : []
    const changed = previousSession && currentSession ? [currentSession] : []

    this.currentSession = currentSession
    this.sessionChangeEmitter.fire({ added, removed, changed })
  }

  private async getStoredSessions(): Promise<AuthenticationSession[]> {
    const allSessions = await this.context.secrets.get(SESSIONS_SECRET_KEY)
    if (!allSessions) {
      return []
    }

    return JSON.parse(allSessions) as AuthenticationSession[]
  }

  private async login(scopes: readonly string[]): Promise<OAuthSession> {
    return window.withProgress(
      {
        location: ProgressLocation.Notification,
        title: 'Signing in to Dynatrace...',
        cancellable: true
      },
      async (_, cancellationToken) => {
        const state = crypto.randomBytes(32).toString('hex')
        const { OAUTH_CODE_CHALLENGE, OAUTH_CODE_VERIFIER } = generateOAuthChallengeAndVerifier()
        const redirectUri = await getAuthRedirectUri()

        const searchParams = new URLSearchParams([
          ['response_type', 'code'],
          ['client_id', this.config.clientId],
          ['redirect_uri', redirectUri],
          ['scope', scopes.join(' ')],
          ['code_challenge', OAUTH_CODE_CHALLENGE],
          ['code_challenge_method', 'S256'],
          ['state', state]
        ])

        let cancel: () => void = () => undefined
        const serverTask = new Promise<OAuthSession>((resolve, reject) => {
          const authServer = new AuthServer(
            (response: AuthResponse) => {
              authServer.killServer()
              if ('error' in response) {
                reject(new Error(response.error))
                return
              }

              resolve(response)
            },
            state,
            OAUTH_CODE_VERIFIER,
            redirectUri,
            this.config.tokenValidator,
            this.config.clientId
          )

          cancel = () => {
            authServer.killServer()
            reject(new Error('Operation was cancelled'))
          }
        })

        const uri = Uri.parse(`${this.config.loginUrl}?${searchParams.toString()}`)
        await env.openExternal(uri)

        cancellationToken.onCancellationRequested(() => {
          cancel()
        })

        return serverTask
      }
    )
  }

  private async assignSession(tokens: OAuthSession, reason: AuthSessionChangeReason): Promise<AuthenticationSession> {
    const decodedAccessToken = decodeJwtPayload(tokens.access_token)
    const session: AuthenticationSession = {
      id: tokens.id_token,
      accessToken: tokens.access_token,
      account: {
        label: '',
        id: decodedAccessToken?.email ?? ''
      },
      scopes: Array.isArray(tokens.scope) ? tokens.scope : [tokens.scope]
    }

    await this.context.secrets.store(SESSIONS_SECRET_KEY, JSON.stringify([session]))
    await this.context.secrets.store(REFRESH_TOKEN_SECRET_KEY, tokens.refresh_token)
    this.currentSession = session

    this.sessionChangeEmitter.fire(
      reason === 'added'
        ? { added: [session], removed: [], changed: [] }
        : { added: [], removed: [], changed: [session] }
    )

    return session
  }

  private async tryRefreshIfNeeded(session: AuthenticationSession): Promise<AuthenticationSession | undefined> {
    const payload = decodeJwtPayload(session.accessToken)
    if (!payload?.exp || payload.exp * 1000 > Date.now()) {
      return undefined
    }

    const refreshToken = await this.context.secrets.get(REFRESH_TOKEN_SECRET_KEY)
    if (!refreshToken) {
      return undefined
    }

    const response = await fetch(this.config.tokenValidator, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.config.clientId,
        refresh_token: refreshToken
      })
    })

    if (!response.ok) {
      return undefined
    }

    const newTokens = (await response.json()) as OAuthSession
    return this.assignSession(newTokens, 'changed')
  }
}

export const getAuthRedirectUri = async (): Promise<string> => {
  const localhostUri = Uri.parse(`http://localhost:${AUTH_PORT}`)
  const externalUri = await env.asExternalUri(localhostUri)
  return externalUri.with({ path: AUTH_PATH, query: '', fragment: '' }).toString()
}

const decodeJwtPayload = (token: string): JwtPayloadLike | undefined => {
  const parts = token.split('.')
  if (parts.length < 2) {
    return undefined
  }

  try {
    const decoded = Buffer.from(parts[1], 'base64url').toString('utf8')
    return JSON.parse(decoded) as JwtPayloadLike
  } catch {
    return undefined
  }
}

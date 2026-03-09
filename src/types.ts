export type OAuthSession = {
  access_token: string
  id_token: string
  token_type: string
  expires_in: number
  refresh_token: string
  scope: string | string[]
}

export type AuthResponse = OAuthSession | { error: string; errorBody?: unknown }

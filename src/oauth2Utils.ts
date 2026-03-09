import crypto from 'crypto'

export const generateOAuthChallengeAndVerifier = (): {
  OAUTH_CODE_VERIFIER: string
  OAUTH_CODE_CHALLENGE: string
} => {
  const OAUTH_CODE_VERIFIER = crypto.randomBytes(32).toString('base64url')
  const OAUTH_CODE_CHALLENGE = crypto
    .createHash('sha256')
    .update(OAUTH_CODE_VERIFIER)
    .digest('base64url')

  return { OAUTH_CODE_CHALLENGE, OAUTH_CODE_VERIFIER }
}

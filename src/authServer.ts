import { createServer, IncomingMessage, Server, ServerResponse } from 'http'
import * as vscode from 'vscode'
import crypto from 'crypto'
import { AuthResponse, OAuthSession } from './types'
import { successPage } from './html/success'
import { failPage } from './html/failure'

const CALLBACK_PATH = '/auth/login'
const CALLBACK_PORT = 3232

export class AuthServer {
  public server!: Server

  public constructor(
    private callback: (token: AuthResponse) => unknown,
    private expectedState: string,
    private codeVerifier: string,
    private redirectUri: string,
    private tokenValidator: string,
    private clientId: string
  ) {
    this.initServer()
  }

  private initServer(): void {
    this.server = createServer((request, response) => {
      void this.handleRequest(request, response)
    })
    this.server.listen(CALLBACK_PORT, '0.0.0.0')
    this.server.on('error', (error: unknown) => {
      this.callback({ error: 'Auth callback server failed to start', errorBody: error })
    })
  }

  public killServer(): void {
    this.server.close()
  }

  private async handleRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (request.method !== 'GET') {
      this.sendHtml(response, 405, 'Method Not Allowed')
      return
    }

    const parsedUrl = new URL(request.url ?? '/', `http://127.0.0.1:${CALLBACK_PORT}`)
    if (parsedUrl.pathname !== CALLBACK_PATH) {
      this.sendHtml(response, 404, 'Not Found')
      return
    }

    const code = parsedUrl.searchParams.get('code')
    const state = parsedUrl.searchParams.get('state')
    if (!code) {
      this.sendHtml(response, 400, "Couldn't log you in")
      this.callback({ error: 'code is not presented' })
      return
    }
    if (!state || !this.isStateValid(state)) {
      this.sendHtml(response, 400, failPage)
      this.callback({ error: 'Invalid OAuth state' })
      return
    }

    try {
      const result = await this.postData(code)
      if (result.id_token) {
        this.sendHtml(response, 200, successPage(vscode.env.uriScheme))
        this.callback(result)
        return
      }
      this.sendHtml(response, 400, failPage)
    } catch (error: unknown) {
      this.sendHtml(response, 500, failPage)
      this.callback({ error: 'Error on request', errorBody: error })
    }
  }

  private sendHtml(response: ServerResponse, status: number, body: string): void {
    response.statusCode = status
    response.setHeader('Content-Type', 'text/html; charset=utf-8')
    response.end(body)
  }

  public async postData(code: string): Promise<OAuthSession> {
    const params = new URLSearchParams()
    params.append('grant_type', 'authorization_code')
    params.append('code', code)
    params.append('client_id', this.clientId)
    params.append('redirect_uri', this.redirectUri)
    params.append('code_verifier', this.codeVerifier)

    const response = await fetch(this.tokenValidator, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params
    })

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`)
    }

    return (await response.json()) as OAuthSession
  }

  private isStateValid(state: string): boolean {
    const expectedStateBuffer = Buffer.from(this.expectedState)
    const actualStateBuffer = Buffer.from(state)
    if (expectedStateBuffer.length !== actualStateBuffer.length) {
      return false
    }

    return crypto.timingSafeEqual(expectedStateBuffer, actualStateBuffer)
  }
}

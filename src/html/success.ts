export const successPage = (uriScheme: string): string => `<!DOCTYPE html><html><body><h1>Login successful</h1><script>window.location.href='${uriScheme}://';</script></body></html>`

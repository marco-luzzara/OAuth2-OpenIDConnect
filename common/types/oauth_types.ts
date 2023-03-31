export type PKCEParams = {
    code_challenge: string,
    code_challenge_method: 'S256'
}

export type OAuthRequestQueryParams = {
    response_type: 'code',
    client_id: string,
    redirect_uri: string,
    scope: string,
    state: string
} & PKCEParams

export type AuthCodePayload = {
    client_id: string,
    redirect_uri: string,
    scope: string
} & PKCEParams

export type OAuthRedirectionQueryParams = {
    code: string,
    state: string
}

export type AccessTokenExchangeResponse = {
    token_type: "Bearer",
    expires_in: number,
    access_token: string,
    refresh_token: string
}

export type AccessTokenExchangeBody = {
    code: string,
    grant_type: 'authorization_code',
    redirect_uri: string,
    client_id: string,
    client_secret: string,
    code_verifier: string
}

export type RefreshTokenExchangeBody = {
    grant_type: 'refresh_token',
    refresh_token: string,
    client_id: string,
    client_secret: string
}

export type AccessTokenPayload = {
    client_id: string,
    scope: string
}

export type RefreshTokenPayload = {
    client_id: string,
    scope: string
}

export type TokenBasicPayload = {
    jti: string,
    sub: string,
    iss: string,
    aud: string
}

export type AccessTokenExtendedPayload = AccessTokenPayload & TokenBasicPayload
export type RefreshTokenExtendedPayload = RefreshTokenPayload & TokenBasicPayload
export type AuthCodeExtendedPayload = AuthCodePayload & TokenBasicPayload
import * as t from 'io-ts'
import { OAuthRequestQueryParams } from '../../../common/types/oauth_types';
import { generateUrlWithQueryParams } from '../../../common/utils/generationUtils';
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'
import { Scope } from '../db/Scope';

export const ClientAuthorizationQueryParamsTypeCheck = t.type({
    response_type: t.literal('code'),
    client_id: t.string,
    redirect_uri: HttpLink,
    scope: t.string,
    state: t.string,
    code_challenge: t.string,
    code_challenge_method: t.literal('S256')
})

export const AuthQueryParamsWithUserChoiceTypeCheck = t.type({
    ...ClientAuthorizationQueryParamsTypeCheck.props,
    ...t.type({
        user_choice: t.union([t.literal('allow'), t.literal('deny')])
    }).props
})

export type ValidatedAuthRequestParams = Omit<OAuthRequestQueryParams, 'scope'> & {
    applicationName: string,
    scope: Scope[]
}

export class OAuthCodeFailedRequest {
    readonly redirectUri: string
    readonly error: string
    readonly errorDescription: string

    constructor(redirectUri: string, error: string, errorDescription: string) {
        this.redirectUri = redirectUri
        this.error = error
        this.errorDescription = errorDescription
    }

    buildCompleteUri(): string {
        return generateUrlWithQueryParams(this.redirectUri, {
            error: this.error,
            error_description: this.errorDescription
        })
    }
}
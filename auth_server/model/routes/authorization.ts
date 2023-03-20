import * as t from 'io-ts'
import { generateUrlWithQueryParams } from '../../../common/utils/generationUtils';
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'
import { Scope } from '../db/Scope';

export const ClientAuthorizationQueryParams = t.type({
    response_type: t.union([t.literal('code'), t.literal('implicit')]),
    client_id: t.string,
    redirect_uri: HttpLink,
    scope: t.string,
    state: t.string
})

export const AuthQueryParamsWithUserChoice = t.type({
    ...ClientAuthorizationQueryParams.props,
    ...t.type({
        user_choice: t.union([t.literal('allow'), t.literal('deny')])
    }).props
})

export type AuthRequestParamsShared = {
    response_type: "code" | "implicit";
    client_id: string;
    redirect_uri: string;
    state: string;
}
export type AuthRequestParams = AuthRequestParamsShared & {
    scope: string;
}
export type ValidatedAuthRequestParams = AuthRequestParamsShared & {
    applicationName: string,
    scope: Scope[]
}

export class OAuthErrorResponse {
    readonly redirectUri: string
    readonly state: string
    readonly error: string
    readonly errorDescription: string

    constructor(redirectUri: string, state: string, error: string, errorDescription: string) {
        this.redirectUri = redirectUri
        this.state = state
        this.error = error
        this.errorDescription = errorDescription
    }

    buildCompleteUri(): string {
        return generateUrlWithQueryParams(this.redirectUri, {
            error: this.error,
            error_description: this.errorDescription,
            state: this.state
        })
    }
}
import * as t from 'io-ts'
import { HttpLink } from '../../../common/utils/io-ts-extension/refinements/Link'
import { Scope } from '../db/Scope';

export const ClientAuthorizationQueryParams = t.type({
    response_type: t.union([t.literal('code'), t.literal('implicit')]),
    client_id: t.string,
    redirect_uri: HttpLink,
    scope: t.string,
    state: t.string
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
import * as t from 'io-ts'

// https://stackoverflow.com/a/43467144/5587393
function isValidHttpUrl(s: string): boolean {
    let url;
    try {
        url = new URL(s)
    } catch (_) {
        return false
    }

    return url.protocol === "http:" || url.protocol === "https:"
}

// see https://github.com/gcanti/io-ts/blob/master/index.md#branded-types--refinements
interface HttpLinkBrand {
    readonly HttpLink: unique symbol
}

export const HttpLink = t.brand(
    t.string,
    (s): s is t.Branded<string, HttpLinkBrand> => isValidHttpUrl(s),
    'HttpLink'
)

export type HttpLink = t.TypeOf<typeof HttpLink>
import { Middleware, Context, DefaultContext } from 'koa';
import tokenIntrospection from 'token-introspection';

type Json =
    | string
    | number
    | boolean
    | null
    | { [property: string]: Json }
    | Json[];

export type IntrospectionSettings = {
    endpoint: string,
    allowed_algs?: string,
    jwks_cache_enabled?: boolean, //defaults to true
    jwks_cache_maxentries?: number,
    jwks_cache_time?: number,
    jwks_ratelimit_enabled?: boolean,
    jwks_ratelimit_per_minute?: number,
    user_agent?: string,
    proxy?: string
} & ({ client_id: string, client_secret: string } | { access_token: string }) & ({ jwks: { keys: { kty: string, n: string, e: string }[] } } | { jwks_uri: string });

export function createTokenIntrospectionMiddleware<DecodedToken>(settings: IntrospectionSettings, enforce?: boolean, tokenDecoder?: (token: Json) => DecodedToken): Middleware<DefaultContext> {
    const decoder = tokenDecoder ?? ((token: Json) => token);
    const validator = tokenIntrospection(settings);
    const bearerLowercase = 'bearer ';

    return async (ctx: Context, next: () => Promise<any>) => {
        const authorization = ctx.request.get('Authorization');
        if (authorization && authorization.toLowerCase().startsWith(bearerLowercase)) {
            const token = authorization.substr(bearerLowercase.length);
            try {
                const result = (await validator(token)) as Json & { active: boolean };
                if (result.active) {
                    const decoded = decoder(result);
                    ctx.state.user = decoded;
                } else {
                    ctx.throw(401);
                }
            } catch (e) {
                ctx.throw(401);
            }
        } else if (enforce) {
            ctx.throw(401);
        }
        await next();
    };
}

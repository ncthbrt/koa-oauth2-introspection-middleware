import { Middleware, Context, DefaultContext } from 'koa';
import tokenIntrospection from 'token-introspection';

type Json =
    | string
    | number
    | boolean
    | null
    | { [property: string]: Json }
    | Json[];

export type TokenIntrospectionSettings = IntrospectionSettings;

export function createTokenIntrospectionMiddleware<DecodedToken>(setttings: TokenIntrospectionSettings, enforce?: boolean, tokenDecoder?: (token: Json) => DecodedToken): Middleware<DefaultContext> {
    const decoder = tokenDecoder ?? ((token: Json) => token);
    const validator = tokenIntrospection(setttings);
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

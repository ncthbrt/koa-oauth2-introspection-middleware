type IntrospectionSettings = {
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



type IntrospectionValidation = (token: string) => Promise<{ active: boolean } & unknown>;

declare module "token-introspection" {
    class IntrospectionError extends Error { }
    class ConfigurationError extends Error { }
    class TokenNotActiveError extends Error { }
    class TokenExpiredError extends TokenNotActiveError { }
    class NotBeforeError extends TokenNotActiveError { }

    export default function (settings: IntrospectionSettings): IntrospectionValidation;
}

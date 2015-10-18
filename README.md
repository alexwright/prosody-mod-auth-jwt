# mod_auth_internal_jwt

A Prosody SASL module to authenticate users using a JWT (JSON Wet Token).

## Example Config

    VirtualHost "host.tld"
        authentication = "internal_jwt"
        jwt_signing_secret = "something-decently-secret-with-entropy"
        ssl = {
            -- Setup TLS Ok?
            -- Otherwise the token would be clear text and that's bad
        }

## The token

    {
        "jid": "user@host.tld"
    }

## Todo

 * Nonces to prevent replay attacks
 * Timestamps to prevent old tokens authenticating
 * Expiry timestamp for the same reason
 * Per user secrets stored in the manager?
 * More than one secret?

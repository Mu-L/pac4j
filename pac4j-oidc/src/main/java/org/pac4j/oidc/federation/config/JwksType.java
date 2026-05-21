package org.pac4j.oidc.federation.config;

/**
 * JWKS publication mode for federation entity configuration.
 *
 * @author Jerome LELEU
 * @since 6.5.2
 */
public enum JwksType {
    EMBEDDED,
    URI,
    SIGNED_URI
}

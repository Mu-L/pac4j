package org.pac4j.oidc.federation.entity;

/**
 * Entity configuration generator.
 *
 * @author Jerome LELEU
 * @since 6.4.0
 */
public interface EntityConfigurationGenerator {
    /** @deprecated use {@link #getEntityStatementContentType()} instead. */
    @Deprecated
    String getContentType();
    String getEntityStatementContentType();
    String getJwksContentType();
    String generateEntityStatement();
    Object generateJwks();
}

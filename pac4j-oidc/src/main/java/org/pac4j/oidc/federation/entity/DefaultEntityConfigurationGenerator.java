package org.pac4j.oidc.federation.entity;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.util.InitializableObject;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.federation.config.JwksType;

import java.util.*;
import java.util.stream.Collectors;

import static org.pac4j.core.util.CommonHelper.assertNotBlank;
import static org.pac4j.core.util.JwkHelper.*;

/**
 * The default entity configuration generator.
 *
 * @author Jerome LELEU
 * @since 6.4.0
 */
@Slf4j
@RequiredArgsConstructor
public class DefaultEntityConfigurationGenerator extends InitializableObject implements EntityConfigurationGenerator {

    protected static final String ENTITY_STATEMENT_TYPE = "entity-statement+jwt";
    protected static final String SIGNED_JWKS_TYPE = "jwk-set+jwt";
    public static final String ENTITY_STATEMENT_CONTENT_TYPE = "application/" + ENTITY_STATEMENT_TYPE;
    public static final String SIGNED_JWKS_CONTENT_TYPE = "application/" + SIGNED_JWKS_TYPE;

    /** @deprecated use {@link #ENTITY_STATEMENT_CONTENT_TYPE} or {@link #SIGNED_JWKS_CONTENT_TYPE}. */
    @Deprecated
    public static final String CONTENT_TYPE = ENTITY_STATEMENT_CONTENT_TYPE;

    private final OidcClient client;
    private String statement;

    /** Exposed JWKS value when publication mode is URI (JSON object) or SIGNED_URI (signed JWT). */
    @Getter
    private Object jwks;

    @Setter(AccessLevel.PACKAGE)
    private Date expirationDate;

    @Deprecated
    @Override
    public String getContentType() {
        return getEntityStatementContentType();
    }

    @Override
    public String getEntityStatementContentType() {
        return ENTITY_STATEMENT_CONTENT_TYPE;
    }

    @Override
    public String getJwksContentType() {
        val jwksType = getEffectiveJwksType();
        return switch (jwksType) {
            case URI -> HttpConstants.APPLICATION_JSON;
            case SIGNED_URI -> SIGNED_JWKS_CONTENT_TYPE;
            case EMBEDDED -> null;
            default -> throw new TechnicalException("Unsupported federation JWKS type: " + jwksType);
        };
    }

    @Override
    public String generateEntityStatement() {
        init();
        return statement;
    }

    @Override
    public Object generateJwks() {
        init();
        return jwks;
    }

    @Override
    protected boolean shouldInitialize(final boolean forceReinit) {
        val now = new Date();
        if (expirationDate == null || expirationDate.before(now)) {
            return true;
        }

        return super.shouldInitialize(forceReinit);
    }

    @Override
    protected void internalInit(final boolean forceReinit) {
        val config = client.getConfiguration();
        val federation = config.getFederation();
        JWK signingKey = null;
        val jwksProperties = federation.getJwks();
        val keystoreProperties = federation.getKeystore();
        if (jwksProperties != null && jwksProperties.getJwksResource() != null) {
            signingKey = loadJwkFromOrCreateJwks(jwksProperties);
        } else if (keystoreProperties != null && keystoreProperties.getKeystoreResource() != null) {
            signingKey = loadJwkFromOrCreateKeyStore(federation.getKeystore());
        } else {
            throw new TechnicalException("OIDC JWKS or keystore mandatory to generate the entity configuration");
        }

        buildConfig(signingKey);
    }

    protected void buildConfig(final JWK signingKey) {
        if (!hasPrivatePart(signingKey)) {
            throw new TechnicalException("Signing key must include private part");
        }

        val config = client.getConfiguration();
        val federation = config.getFederation();
        val callbackURL = client.computeFinalCallbackUrl(null);
        var entityId = federation.getEntityId();
        if (StringUtils.isBlank(entityId)) {
            entityId = client.getCallbackUrl();
            federation.setEntityId(entityId);
        }
        assertNotBlank("entityId", entityId);
        LOGGER.info("Generating entity configuration for: {}", entityId);

        val now = new Date();
        long validityMs = (long) federation.getValidityInDays() * 24 * 60 * 60 * 1000L;
        expirationDate = new Date(now.getTime() + validityMs);

        val claimsBuilder = new JWTClaimsSet.Builder()
            .issuer(entityId)
            .subject(entityId)
            .jwtID(UUID.randomUUID().toString())
            .issueTime(now)
            .audience(federation.getTargetOp())
            .expirationTime(expirationDate)
            .notBeforeTime(now);

        val rpMetadata = new LinkedHashMap<String, Object>();
        rpMetadata.put("redirect_uris", List.of(callbackURL));
        rpMetadata.put("application_type", federation.getApplicationType());
        rpMetadata.put("response_types", federation.getResponseTypes());
        rpMetadata.put("grant_types", federation.getGrantTypes());
        rpMetadata.put("scope", String.join(" ", federation.getScopes()));
        val clientAuth = config.getClientAuthenticationMethod();
        val keys = new LinkedHashSet<JWK>();
        if (clientAuth != null) {
            rpMetadata.put("token_endpoint_auth_method", clientAuth.getValue());
            if (clientAuth == ClientAuthenticationMethod.PRIVATE_KEY_JWT) {
                val clientAuthConfig = config.getPrivateKeyJwtClientAuthnMethodConfig();
                if (clientAuthConfig != null && clientAuthConfig.getJwsAlgorithm() != null) {
                    rpMetadata.put("token_endpoint_auth_signing_alg", clientAuthConfig.getJwsAlgorithm().getName());
                    val publicKey = clientAuthConfig.getJwk().toPublicJWK();
                    keys.add(publicKey);
                }
            }
        }
        val requestObjectSigningAlg = config.getRequestObjectSigningAlgorithm();
        if (requestObjectSigningAlg != null) {
            rpMetadata.put("request_object_signing_alg", requestObjectSigningAlg.getName());
            val rpJwks = config.getRpJwks();
            if (rpJwks != null && rpJwks.isDefined()) {
                val key = loadJwkFromOrCreateJwks(config.getRpJwks());
                keys.add(key.toPublicJWK());
            }
        }
        if (!keys.isEmpty()) {
            val jwkSet = new JWKSet(new ArrayList<>(keys));
            rpMetadata.put("jwks", jwkSet.toJSONObject());
        }
        rpMetadata.put("client_registration_types", federation.getClientRegistrationTypes());
        rpMetadata.put("client_name", federation.getContactName());
        val contacts = federation.getContactEmails();
        if (contacts != null && contacts.size() > 0) {
            rpMetadata.put("contacts", contacts);
        }

        val metadata = new LinkedHashMap<String, Object>();
        metadata.put("openid_relying_party", rpMetadata);
        val publicJwkSet = new JWKSet(signingKey.toPublicJWK());
        val jwksType = getEffectiveJwksType();
        Object generatedJwks = null;
        switch (jwksType) {
            case EMBEDDED -> {
                claimsBuilder.claim("jwks", publicJwkSet.toJSONObject());
            }
            case URI -> {
                assertNotBlank("federation.exposedJwksUrl", federation.getExposedJwksUrl());
                metadata.put("jwks_uri", federation.getExposedJwksUrl());
                generatedJwks = publicJwkSet.toJSONObject();
            }
            case SIGNED_URI -> {
                assertNotBlank("federation.exposedJwksUrl", federation.getExposedJwksUrl());
                metadata.put("signed_jwks_uri", federation.getExposedJwksUrl());
                val signedJwksClaims = new JWTClaimsSet.Builder()
                    .claim("keys", publicJwkSet.toJSONObject().get("keys"))
                    .issueTime(now)
                    .expirationTime(expirationDate)
                    .build();
                generatedJwks = buildSignedJwt(signedJwksClaims, signingKey, SIGNED_JWKS_TYPE);
            }
            default -> {
                throw new TechnicalException("Unsupported federation JWKS type: " + jwksType);
            }
        }
        claimsBuilder.claim("metadata", metadata);

        val trustAnchors = federation.getTrustAnchors();
        if (trustAnchors != null && trustAnchors.size() > 0) {
            claimsBuilder.claim("authority_hints", trustAnchors.stream().map(ta -> ta.getIssuer()).collect(Collectors.toList()));
        }

        val claims = claimsBuilder.build();
        statement = buildSignedJwt(claims, signingKey, ENTITY_STATEMENT_TYPE);
        jwks = generatedJwks;
    }

    protected JwksType getEffectiveJwksType() {
        val federation = client.getConfiguration().getFederation();
        if (federation == null || federation.getJwksType() == null) {
            return JwksType.EMBEDDED;
        }
        return federation.getJwksType();
    }
}

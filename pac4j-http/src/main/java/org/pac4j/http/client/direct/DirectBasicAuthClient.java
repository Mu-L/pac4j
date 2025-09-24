package org.pac4j.http.client.direct;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.pac4j.core.client.DirectClient;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.credentials.extractor.BasicAuthExtractor;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.core.util.Pac4jConstants;

import static org.pac4j.core.util.CommonHelper.assertNotBlank;

/**
 * <p>This class is the client to authenticate users directly through HTTP basic auth.</p>
 *
 * @author Jerome Leleu
 * @since 1.8.0
 */
@Getter
@Setter
@ToString(callSuper = true)
@Slf4j
public class DirectBasicAuthClient extends DirectClient {

    private String realmName = Pac4jConstants.DEFAULT_REALM_NAME;

    /**
     * <p>Constructor for DirectBasicAuthClient.</p>
     */
    public DirectBasicAuthClient() {
    }

    /**
     * <p>Constructor for DirectBasicAuthClient.</p>
     *
     * @param usernamePasswordAuthenticator a {@link Authenticator} object
     */
    public DirectBasicAuthClient(final Authenticator usernamePasswordAuthenticator) {
        setAuthenticatorIfUndefined(usernamePasswordAuthenticator);
    }

    /**
     * <p>Constructor for DirectBasicAuthClient.</p>
     *
     * @param usernamePasswordAuthenticator a {@link Authenticator} object
     * @param profileCreator a {@link ProfileCreator} object
     */
    public DirectBasicAuthClient(final Authenticator usernamePasswordAuthenticator,
                                 final ProfileCreator profileCreator) {
        setAuthenticatorIfUndefined(usernamePasswordAuthenticator);
        setProfileCreatorIfUndefined(profileCreator);
    }

    /** {@inheritDoc} */
    @Override
    protected void internalInit(final boolean forceReinit) {
        assertNotBlank("realmName", this.realmName);

        setCredentialsExtractorIfUndefined(new BasicAuthExtractor());
    }

    /** {@inheritDoc} */
    @Override
    protected void checkCredentials(final CallContext ctx, final Credentials credentials) {
        val webContext = ctx.webContext();
        if (credentials == null) {
            LOGGER.debug("Adding authenticate basic header");
            // set the www-authenticate in case of error
            webContext.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, "Basic realm=\"" + realmName + "\"");
        } else {
            LOGGER.debug("Remove authenticate header");
            webContext.setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, Pac4jConstants.EMPTY_STRING);
        }
    }
}

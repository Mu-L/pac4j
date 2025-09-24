package org.pac4j.core.client;

import lombok.extern.slf4j.Slf4j;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.Pac4jConstants;

import java.util.Optional;

import static org.pac4j.core.util.CommonHelper.assertNotNull;

/**
 * Direct client: credentials are passed and authentication occurs for every HTTP request.
 *
 * @author Jerome Leleu
 * @since 1.9.0
 */
@Slf4j
public abstract class DirectClient extends BaseClient {

    /** {@inheritDoc} */
    @Override
    protected void beforeInternalInit(final boolean forceReinit) {
        if (saveProfileInSession == null) {
            saveProfileInSession = false;
        }
    }

    /** {@inheritDoc} */
    @Override
    protected final void afterInternalInit(final boolean forceReinit) {
        // ensures components have been properly initialized
        assertNotNull("credentialsExtractor", getCredentialsExtractor());
        assertNotNull("authenticator", getAuthenticator());
        assertNotNull("profileCreator", getProfileCreator());
    }

    /** {@inheritDoc} */
    @Override
    public final Optional<RedirectionAction> getRedirectionAction(final CallContext ctx) {
        throw new UnsupportedOperationException("Direct clients cannot redirect for login");
    }

    /** {@inheritDoc} */
    @Override
    public final HttpAction processLogout(final CallContext ctx, final Credentials credentials) {
        throw new UnsupportedOperationException("Direct clients cannot process logout");
    }

    /** {@inheritDoc} */
    @Override
    public final Optional<RedirectionAction> getLogoutAction(final CallContext ctx, final UserProfile currentProfile,
                                                             final String targetUrl) {
        throw new UnsupportedOperationException("Direct clients cannot redirect for logout");
    }

    /** {@inheritDoc} */
    @Override
    protected void checkCredentials(final CallContext ctx, final Credentials credentials) {
        if (credentials != null) {
            LOGGER.debug("Remove authenticate header");
            ctx.webContext().setResponseHeader(HttpConstants.AUTHENTICATE_HEADER, Pac4jConstants.EMPTY_STRING);
        }
    }
}

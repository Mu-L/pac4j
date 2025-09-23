package org.pac4j.core.authorization.authorizer;

import lombok.val;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.matching.matcher.csrf.DefaultCsrfTokenGenerator;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.core.util.TestsConstants;

import java.util.Date;

/**
 * Tests {@link CsrfAuthorizer}.
 *
 * @author Jerome Leleu
 * @since 1.8.0
 */
public final class CsrfAuthorizerTests implements TestsConstants {

    private CsrfAuthorizer authorizer;

    private long expirationDate;

    @BeforeEach
    public void setUp() {
        authorizer = new CsrfAuthorizer();
        authorizer.setCheckAllRequests(true);
        expirationDate = new Date().getTime() + 1000 * new DefaultCsrfTokenGenerator().getTtlInSeconds();
    }

    @Test
    public void testParameterOk() {
        final WebContext context = MockWebContext.create().addRequestParameter(Pac4jConstants.CSRF_TOKEN, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        assertTrue(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testParameterOkPreviousToken() {
        final WebContext context = MockWebContext.create().addRequestParameter(Pac4jConstants.CSRF_TOKEN, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.PREVIOUS_CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, KEY);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        assertTrue(authorizer.isAuthorized(context, sessionStore, null));
        assertFalse(sessionStore.get(context, Pac4jConstants.PREVIOUS_CSRF_TOKEN).isPresent());
    }

    @Test
    public void testParameterNoExpirationDate() {
        final WebContext context = MockWebContext.create().addRequestParameter(Pac4jConstants.CSRF_TOKEN, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        assertFalse(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testParameterExpiredDate() {
        val expiredDate = new Date().getTime() - 1000;
        final WebContext context = MockWebContext.create().addRequestParameter(Pac4jConstants.CSRF_TOKEN, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expiredDate);
        assertFalse(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testParameterOkNewName() {
        final WebContext context = MockWebContext.create().addRequestParameter(NAME, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        authorizer.setParameterName(NAME);
        assertTrue(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testHeaderOk() {
        final WebContext context = MockWebContext.create().addRequestHeader(Pac4jConstants.CSRF_TOKEN, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context,Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        assertTrue(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testHeaderOkNewName() {
        final WebContext context = MockWebContext.create().addRequestHeader(NAME, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        authorizer.setHeaderName(NAME);
        assertTrue(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testNoToken() {
        final WebContext context = MockWebContext.create();
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        assertFalse(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testNoTokenCheckAll() {
        val context = MockWebContext.create();
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        authorizer.setCheckAllRequests(false);
        assertTrue(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testNoTokenRequest() {
        internalTestNoTokenRequest(HttpConstants.HTTP_METHOD.POST);
        internalTestNoTokenRequest(HttpConstants.HTTP_METHOD.PUT);
        internalTestNoTokenRequest(HttpConstants.HTTP_METHOD.PATCH);
        internalTestNoTokenRequest(HttpConstants.HTTP_METHOD.DELETE);
    }

    private void internalTestNoTokenRequest(final HttpConstants.HTTP_METHOD method) {
        val context = MockWebContext.create();
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN, VALUE);
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        context.setRequestMethod(method.name());
        assertFalse(authorizer.isAuthorized(context, sessionStore, null));
    }

    @Test
    public void testHeaderOkButNoTokenInSession() {
        final WebContext context = MockWebContext.create().addRequestHeader(Pac4jConstants.CSRF_TOKEN, VALUE);
        final SessionStore sessionStore = new MockSessionStore();
        sessionStore.set(context, Pac4jConstants.CSRF_TOKEN_EXPIRATION_DATE, expirationDate);
        assertFalse(authorizer.isAuthorized(context, sessionStore, null));
    }
}

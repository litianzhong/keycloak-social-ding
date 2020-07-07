package org.skymid.keycloak.ding;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

/**
 * <a href="https://ding-doc.dingtalk.com/doc#/serverapi2/kymkv6">参考文档</a>
 *
 * @author Brook.li
 */
public class DingIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    //第一步: 请求CODE
    public static final String AUTH_URL = "https://oapi.dingtalk.com/connect/qrconnect";
    // 应用授权作用域，拥有多个作用域用逗号（,）分隔，网页应用目前仅填写snsapi_login即可
    public static final String DEFAULT_SCOPE = "snsapi_login";
    public static final String DING_DEFAULT_SCOPE = "snsapi_userinfo";
    public static final String PROFILE_URL = "https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=APPID" +
        "&timestamp=CURRENT_TIME&signature=CODE_CERT";
    public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";

    public DingIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
    }


    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }


    protected boolean supportsExternalExchange() {
        return true;
    }

    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        JsonNode userInfo = profile.get("user_info");
        String unionid = getJsonProperty(userInfo, "unionid");
        BrokeredIdentityContext user = new BrokeredIdentityContext(
            (unionid != null && unionid.length() > 0 ? unionid : getJsonProperty(userInfo, "openid")));
        String name = getJsonProperty(userInfo, "nick");
        user.setUsername(name);
        user.setBrokerUserId(getJsonProperty(userInfo, "openid"));
        user.setModelUsername(name);
        user.setName(name);
        user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    public BrokeredIdentityContext getFederatedIdentity(String authorizationCode) {
        BrokeredIdentityContext context = null;
        String currentTime = String.valueOf(System.currentTimeMillis());
        try {
            JsonNode profile = null;
            String url = PROFILE_URL.replace("APPID", getConfig().getClientId()).replace("CURRENT_TIME", currentTime)
                .replace("CODE_CERT", this.genSignature(currentTime));
            logger.info("url:" + url);
            Map<String, String> json = new HashMap<>();
            json.put("tmp_auth_code", authorizationCode);
            profile = SimpleHttp.doPost(url, session).json(json).header("Accept-Charset","utf-8").asJson();
            logger.info("get userInfo =" + profile.toString());
            context = extractIdentityFromProfile(null, profile);
        } catch ( Exception e ) {
            logger.error(e);
        }

        context.getContextData().put(FEDERATED_ACCESS_TOKEN, authorizationCode);

        return context;
    }

    private String genSignature(String currentTime) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(getConfig().getClientSecret().getBytes("UTF-8"), "HmacSHA256"));
        byte[] signatureBytes = mac.doFinal(currentTime.getBytes("UTF-8"));
        return urlEncode(Base64.getEncoder().encodeToString(signatureBytes), "UTF-8");
    }

    private String urlEncode(String value, String encoding) {
        if (value == null) {
            return "";
        }
        try {
            String encoded = URLEncoder.encode(value, encoding);
            return encoded.replace("+", "%20").replace("*", "%2A")
                .replace("~", "%7E").replace("/", "%2F");
        } catch ( UnsupportedEncodingException e ) {
            throw new IllegalArgumentException("FailedToEncodeUri", e);
        }
    }

    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            return Response.seeOther(authorizationUrl).build();
        } catch ( Exception e ) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

        final UriBuilder uriBuilder;
        uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
        uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
            .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
            .queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
            .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
            .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (getConfig().isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        String prompt = getConfig().getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = UUID.randomUUID().toString();
            request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }
        return uriBuilder;
    }


    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        @Context
        protected UriInfo uriInfo;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            logger.info("OAUTH2_PARAMETER_CODE=" + authorizationCode);
            if (error != null) {
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
                    return callback.cancelled(state);
                } else {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }

            try {
                BrokeredIdentityContext federatedIdentity = null;
                if (authorizationCode != null) {
                    federatedIdentity = getFederatedIdentity(authorizationCode);

                    if (getConfig().isStoreToken()) {
                        if (federatedIdentity.getToken() == null)
                            federatedIdentity.setToken(authorizationCode);
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(DingIdentityProvider.this);
                    federatedIdentity.setCode(state);

                    return callback.authenticated(federatedIdentity);
                }
            } catch ( WebApplicationException e ) {
                return e.getResponse();
            } catch ( Exception e ) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY,
                Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

    }
}

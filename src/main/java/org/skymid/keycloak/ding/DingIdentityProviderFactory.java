package org.skymid.keycloak.ding;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * @author jacky.yong
 */
public class DingIdentityProviderFactory extends AbstractIdentityProviderFactory<DingIdentityProvider>
        implements SocialIdentityProviderFactory<DingIdentityProvider> {

    public static final String PROVIDER_ID = "ding";

    public String getName() {
        return "Ding";
    }

    public DingIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new DingIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    public String getId() {
        return PROVIDER_ID;
    }
}

package me.omniops.users;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;

@ApplicationScoped
public class KeycloakConnection {

    @Inject
    PortalConfig portalConfig;


    public Keycloak getConnection() {
        return KeycloakBuilder.builder()
                .serverUrl(portalConfig.config().sso().domain())
                .realm("master")
                .clientId(portalConfig.config().sso().clientId())
                .clientSecret(portalConfig.config().sso().clientSecret())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

    public RealmResource getRealmConnection() {
        return KeycloakBuilder.builder()
                .serverUrl(portalConfig.config().sso().domain())
                .realm("master")
                .clientId(portalConfig.config().sso().clientId())
                .clientSecret(portalConfig.config().sso().clientSecret())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build().realm("omniops");
    }
}

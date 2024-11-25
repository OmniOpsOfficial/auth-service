package me.omniops.users;

import jakarta.enterprise.context.ApplicationScoped;
import org.keycloak.admin.client.resource.UserResource;

@ApplicationScoped
public class UserService extends KeycloakConnection {

    public String getUserById(String userId) {
        return getRealmConnection().users().get(userId).toRepresentation().getEmail();
    }
}

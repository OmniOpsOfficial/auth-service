package me.omniops.users;

import jakarta.enterprise.context.ApplicationScoped;
import me.omniops.security.Role;
import me.omniops.security.UserInfo;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.List;

@ApplicationScoped
public class UserService extends KeycloakConnection {

    public String getUserById(String userId) {
        return getRealmConnection().users().get(userId).toRepresentation().getEmail();
    }

    public List<UserInfo> getDetails(Role role){
        return getRealmConnection().roles().get(role.name()).getUserMembers().stream().map(this::toUserInfo).toList();
    }

    private UserInfo toUserInfo(UserRepresentation user) {
       return new UserInfo(user.getId(), user.getUsername(), user.getFirstName(), user.getLastName(), user.getEmail(), null,null,null,null);
    }
}

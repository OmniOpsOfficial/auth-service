package me.omniops.users;

import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;
import me.omniops.security.Role;
import me.omniops.security.UserInfo;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.*;

@Slf4j
@ApplicationScoped
public class UserService extends KeycloakConnection {

    public String getUserById(String userId) {
        return getRealmConnection().users().get(userId).toRepresentation().getEmail();
    }

    public UserRepresentation getUserByIdAsObject(String userId) {
        return getRealmConnection().users().get(userId).toRepresentation();
    }


    public List<UserInfo> getDetails(Role role){
        return getRealmConnection().roles().get(role.name()).getUserMembers().stream().map(this::toUserInfo).toList();
    }

    private UserInfo toUserInfo(UserRepresentation user) {
       return new UserInfo(user.getId(), user.getUsername(), user.getFirstName(), user.getLastName(), user.getEmail(), null,null,null,null);
    }

    /**
     * Updates the user notification status based on the provided template code and sent status.
     *
     * @param userId       The unique identifier of the user. Must not be null or empty.
     * @param templateCode The code of the notification template. Must not be null or empty.
     * @param isSent       The status indicating whether the notification has been sent. Must not be null.
     * @throws IllegalArgumentException if any of the parameters are invalid.
     */
    public void updateUserNotificationStatus(String userId, String templateCode, Boolean isSent) {
        log.info("Attempting to update notification for userId: {}, templateCode: {}", userId, templateCode);
        // Validate input parameters
        validateInputs(userId, templateCode, isSent);
        UserRepresentation user = getRealmConnection().users().get(userId).toRepresentation();
        Map<String, List<String>> attributes = Optional.ofNullable(user.getAttributes()).orElse(new HashMap<>());
        if (!attributes.containsKey(templateCode)) {
            attributes.put(templateCode, Collections.singletonList(String.valueOf(isSent)));
            user.setAttributes(attributes);
            getRealmConnection().users().get(userId).update(user);
            log.info("User updated: {}", user.getId());
        }

//        attributes.forEach((key, value) -> {
//            System.out.println("Key: " + key + ", Values: " + value);
//        });
    }

    private void validateInputs(String userId, String templateCode, Boolean isSent) {
        if (Objects.isNull(userId) || userId.trim().isEmpty()) {
            log.error("Invalid userId: {}", userId);
            throw new IllegalArgumentException("userId must not be null or empty");
        }
        if (Objects.isNull(templateCode) || templateCode.trim().isEmpty()) {
            log.error("Invalid templateCode: {}", templateCode);
            throw new IllegalArgumentException("templateCode must not be null or empty");
        }
        if (Objects.isNull(isSent)) {
            log.error("isSent must not be null");
            throw new IllegalArgumentException("isSent must not be null");
        }
    }
}

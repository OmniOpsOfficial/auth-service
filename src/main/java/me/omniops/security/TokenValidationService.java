package me.omniops.security;

import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@ApplicationScoped
public class TokenValidationService {

    private final SecurityIdentity securityIdentity;

    public TokenValidationService(SecurityIdentity securityIdentity) {
        this.securityIdentity = securityIdentity;
    }

    public Optional<UserInfo> validateTokenAndExtractClaims(List<Role> requiredRoles) {
        TokenCredential credential = securityIdentity.getCredential(TokenCredential.class);
        var claims = OidcUtils.decodeJwtContent(credential.getToken());

        String userId = getClaimValue(claims, "sub");
        String username = getClaimValue(claims, "preferred_username");
        String email = getClaimValue(claims, "email");
        String givenName = getClaimValue(claims, "given_name");
        String familyName = getClaimValue(claims, "family_name");

        List<String> roles = extractJsonArray(claims, "realm_access", "roles");
        List<String> groups = extractJsonArray(claims, "groups");
        List<String> modules = extractJsonArray(claims, "modules");
        UserInfo userInfo = new UserInfo(
                userId,
                username,
                givenName,
                familyName,
                email,
                roles,
                groups,
                modules,
                null
        );

        boolean isAuthorized = requiredRoles.stream()
                .map(Role::name)
                .map(String::toLowerCase)
                .anyMatch(role -> userInfo.getRoles().stream()
                        .map(String::toLowerCase)
                        .anyMatch(role::equals));
        return isAuthorized ? Optional.of(userInfo) : Optional.empty();
    }


    private String getClaimValue(JsonObject claims, String key) {
        return claims.getString(key, null);
    }

    private List<String> extractJsonArray(JsonObject claims, String arrayKey) {
        return extractJsonArray(claims, null, arrayKey);
    }

    private List<String> extractJsonArray(JsonObject claims, String objectKey, String arrayKey) {
        List<String> values = new ArrayList<>();
        if (objectKey == null || claims.containsKey(objectKey)) {
            JsonArray jsonArray = objectKey == null ? claims.getJsonArray(arrayKey) : claims.getJsonObject(objectKey).getJsonArray(arrayKey);
            if (jsonArray != null) {
                for (int i = 0; i < jsonArray.size(); i++) {
                    values.add(jsonArray.getString(i));
                }
            }
        }
        return values;
    }
}


//    private String getClaimValue(JsonObject claims, String key, String defaultValue) {
//        return Optional.ofNullable(claims.getString(key, null)).orElse(defaultValue);
//    }

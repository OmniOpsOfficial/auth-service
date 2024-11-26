package me.omniops.security;

import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@ApplicationScoped
public class TokenValidationService {

    private final SecurityIdentity securityIdentity;

    @Inject
    public TokenValidationService(SecurityIdentity securityIdentity) {
        this.securityIdentity = securityIdentity;
    }

    public Optional<UserInfo> validateTokenAndExtractClaims(List<Role> requiredRoles, List<Modules> requiredModules) {
        log.warn("Validating token with required roles: {} and modules: {}", requiredRoles, requiredModules);
        TokenCredential credential = securityIdentity.getCredential(TokenCredential.class);
        if (credential == null) {
            log.warn("Token credential is missing.");
            return Optional.empty();
        }
        JsonObject claims;
        try {
            claims = OidcUtils.decodeJwtContent(credential.getToken());
        } catch (Exception e) {
            log.error("Failed to decode JWT content: {}", e.getMessage(), e);
            return Optional.empty();
        }
        UserInfo userInfo = extractUserInfo(claims);
        if (userInfo == null) {
            log.warn("Failed to extract user information from token.");
            return Optional.empty();
        }
        log.warn("Extracted UserInfo: {}", userInfo);
        if (isAuthorized(userInfo, requiredRoles, requiredModules)) {
            return Optional.of(userInfo);
        }
        log.info("User [{}] is not authorized for the specified roles/modules", userInfo.getUsername());
        return Optional.empty();
    }

    private UserInfo extractUserInfo(JsonObject claims) {
        try {
            String userId = getClaimValue(claims, "sub");
            String username = getClaimValue(claims, "preferred_username");
            String email = getClaimValue(claims, "email");
            String givenName = getClaimValue(claims, "given_name");
            String familyName = getClaimValue(claims, "family_name");
//            List<String> roles = extractJsonArray(claims, "realm_access", "roles");
            List<String> roles = extractJsonArray(claims, "roles");
            List<String> groups = extractJsonArray(claims, "groups");
            List<String> userModules = extractJsonArray(claims, "modules");
            return new UserInfo(userId, username, givenName, familyName, email, roles, groups, userModules, null);
        } catch (Exception e) {
            log.error("Error extracting UserInfo from claims: {}", e.getMessage(), e);
            return null;
        }
    }

    private boolean isAuthorized(UserInfo userInfo, List<Role> requiredRoles, List<Modules> requiredModules) {
        boolean hasRequiredRoles = hasMatchingRoles(userInfo.getRoles(), requiredRoles);
        boolean hasRequiredModules = hasMatchingModules(userInfo.getModels(), requiredModules);
        log.warn("User has required roles: {}, required modules: {}", hasRequiredRoles, hasRequiredModules);
        return hasRequiredRoles && hasRequiredModules;
    }

    private boolean hasMatchingRoles(List<String> userRoles, List<Role> requiredRoles) {
            return requiredRoles.stream()
                .map(role -> role.name().toLowerCase())
                .anyMatch(userRoles.stream().map(String::toLowerCase).collect(Collectors.toSet())::contains);
    }

    private boolean hasMatchingModules(List<String> userModules, List<Modules> requiredModules) {
        return requiredModules.stream()
                .map(module -> module.name().toLowerCase())
                .anyMatch(userModules.stream().map(String::toLowerCase).collect(Collectors.toSet())::contains);
    }

    private String getClaimValue(JsonObject claims, String key) {
        return claims != null ? claims.getString(key, null) : null;
    }

    private List<String> extractJsonArray(JsonObject claims, String arrayKey) {
        return extractJsonArray(claims, null, arrayKey);
    }

    private List<String> extractJsonArray(JsonObject claims, String objectKey, String arrayKey) {
        if (claims == null || (objectKey != null && !claims.containsKey(objectKey))) {
            return Collections.emptyList();
        }
        JsonArray jsonArray = objectKey == null ? claims.getJsonArray(arrayKey)
                : claims.getJsonObject(objectKey).getJsonArray(arrayKey);
        if (jsonArray == null) {
            return Collections.emptyList();
        }
        return jsonArray.stream()
                .map(Object::toString)
                .collect(Collectors.toList());
    }
}

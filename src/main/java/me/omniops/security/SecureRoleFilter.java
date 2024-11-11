package me.omniops.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import java.lang.reflect.AnnotatedElement;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Provider
@Priority(0)
public class SecureRoleFilter implements ContainerRequestFilter {

    @Inject
    TokenValidationService tokenValidationService;
    @Context
    private ResourceInfo resourceInfo;
    private static final String USER_INFO_HEADER = "X-User-Info";

    @Override
    public void filter(ContainerRequestContext requestContext) {
        log.debug("Start Security filter...");
        try {
            Optional<UserInfo> userInfoOpt = tokenValidationService.validateTokenAndExtractClaims(getRoles(), getModules());
            if (userInfoOpt.isEmpty()) {
                log.warn("Unauthorized access: Missing or invalid roles/modules");
                throw new AuthorizationException("Unauthorized Role");
            }
            UserInfo userInfo = userInfoOpt.get();
            log.debug("User Info: {}", userInfo);
            requestContext.getHeaders().add(USER_INFO_HEADER, serializeUserInfo(userInfo));
        } catch (AuthorizationException e) {
            log.error("Authorization error: {}", e.getMessage());
            abortRequest(requestContext, Response.Status.FORBIDDEN, "Authorization failed");
        } catch (Exception e) {
            log.error("Token validation failed due to unexpected error: {}", e.getMessage(), e);
            abortRequest(requestContext, Response.Status.UNAUTHORIZED, "Token validation failed");
        }
    }

    private List<Modules> getModules() {
        return Optional.ofNullable(extractModules(resourceInfo.getResourceMethod()))
                .filter(modules -> !modules.isEmpty())
                .orElseGet(() -> extractModules(resourceInfo.getResourceClass()));
    }

    private List<Role> getRoles() {
        return Optional.ofNullable(extractRoles(resourceInfo.getResourceMethod()))
                .filter(roles -> !roles.isEmpty())
                .orElseGet(() -> extractRoles(resourceInfo.getResourceClass()));
    }

    private List<Role> extractRoles(AnnotatedElement element) {
        return Optional.ofNullable(element)
                .map(e -> e.getAnnotation(Authorization.class))
                .map(auth -> Arrays.asList(auth.roles()))
                .orElseGet(Collections::emptyList);
    }

    private List<Modules> extractModules(AnnotatedElement element) {
        return Optional.ofNullable(element)
                .map(e -> e.getAnnotation(Authorization.class))
                .map(auth -> Arrays.asList(auth.modules()))
                .orElseGet(Collections::emptyList);
    }

    private String serializeUserInfo(UserInfo userInfo) {
        try {
            return Base64.getEncoder().encodeToString(new ObjectMapper().writeValueAsString(userInfo).getBytes(StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    private void abortRequest(ContainerRequestContext requestContext, Response.Status status, String message) {
        requestContext.abortWith(Response.status(status)
                .entity(message)
                .type(MediaType.APPLICATION_JSON)
                .build());
    }
}
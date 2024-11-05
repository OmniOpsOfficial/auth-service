package me.omniops.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
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

    @Override
    public void filter(ContainerRequestContext requestContext) {
        List<Role> resourceRoles = extractRoles(resourceInfo.getResourceClass());
        List<Role> methodRoles = extractRoles(resourceInfo.getResourceMethod());
        try {
            Optional<UserInfo> userInfo = tokenValidationService.validateTokenAndExtractClaims(methodRoles.isEmpty() ? resourceRoles : methodRoles);
            if (userInfo.isPresent()) {
                log.debug(" User Info [ {} ] ", userInfo);
                requestContext.getHeaders().add("X-User-Info", serializeUserInfo(userInfo.get())); // Serialize UserInfo to a string
            }else {
                throw new AuthorizationException("Unauthorized Role");
            }
        } catch (Exception e) {
            throw new ForbiddenException("Token validation failed: " + e.getMessage());
        }
    }


    protected List<Role> extractRoles(AnnotatedElement element) {
        if (Objects.nonNull(element.getAnnotation(Authorization.class))) {
            return Arrays.asList(element.getAnnotation(Authorization.class).value());
        }
        return new ArrayList<>();
    }

    private String serializeUserInfo(UserInfo userInfo) {
        try {
            return Base64.getEncoder().encodeToString(new ObjectMapper().writeValueAsString(userInfo).getBytes(StandardCharsets.UTF_8));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
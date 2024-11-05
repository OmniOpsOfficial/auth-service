package me.omniops.security;

import io.quarkus.oidc.OIDCException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import org.jboss.logging.Logger;

@Slf4j
@Provider
public class OIDCExceptionMapper implements ExceptionMapper<OIDCException> {
    @Override
    public Response toResponse(OIDCException exception) {
        // Log the exception details for debugging
       log.error("OIDC exception occurred: {} " , exception.getMessage());
        // Customize the response
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity("Token-related error: " + exception.getMessage())
                .build();
    }
}
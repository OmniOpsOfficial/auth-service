package me.omniops.security;

import io.quarkus.oidc.OIDCException;
import io.quarkus.security.AuthenticationFailedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Provider
public class OIDCExceptionMapper implements ExceptionMapper<OIDCException> {


    @Override
    public Response toResponse(OIDCException exception) {
        String message = "Authentication error occurred.";

        Throwable cause = exception.getCause();
        if (cause != null) {
            String causeMessage = cause.getMessage();
            if (causeMessage != null) {
                if (causeMessage.contains("expired")) {
                    message = "Token has expired.";
                } else if (causeMessage.contains("invalid")) {
                    message = "Token is invalid.";
                } else if (causeMessage.contains("issuer")) {
                    message = "Token issuer is incorrect.";
                }
            }
        }
        return Response.status(Response.Status.UNAUTHORIZED).entity(message).build();
    }

//    @Override
//    public Response toResponse(OIDCException exception) {
//       log.error("OIDC exception occurred: {} " , exception.getMessage());
//
//        return Response.status(Response.Status.UNAUTHORIZED)
//                .entity("Token-related error: " + exception.getMessage())
//                .build();
//
//    }
}
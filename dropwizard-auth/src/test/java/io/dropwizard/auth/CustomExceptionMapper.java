package io.dropwizard.auth;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

public class CustomExceptionMapper implements ExceptionMapper<Exception> {

    @Override
    public Response toResponse(final Exception exception) {
        return Response.status(599) //
                .entity(exception.getMessage()) //
                .type("text/plain") //
                .build();
    }
}

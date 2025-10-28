package com.security.securityDemo.jwt.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.lang.runtime.ObjectMethods;
import java.util.HashMap;
import java.util.Map;

/*
Whenever a request tries to access a protected endpoint without valid authentication
(e.g., missing or invalid JWT), Spring Security triggers this component.
It decides how to respond to unauthorized access — instead of showing a default HTML error page, it returns a clean JSON response.
 */

@Component
//'AuthenticationEntryPoint': This is an interface from Spring Security used to handle unauthorized access attempts.
// AuthEntryPointJwt is only responsible for returning an error response, when token is invalid or missing
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    // commence() method
    //This method runs every time an unauthorized request hits your API.
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException {
            logger.error("Unauthorized error: {}",authException.getMessage());
            // ensures the API returns JSON, not HTML
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            // Sends HTTP 401(unauthorized) to the client
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            // Builds a custom JSON response body
            final Map<String, Object> body = new HashMap<>();
            body.put("status",HttpServletResponse.SC_UNAUTHORIZED);
            body.put("message",authException.getMessage());
            body.put("path",request.getServletPath());

            //Write the JSON to the response output
            final ObjectMapper mapper = new ObjectMapper();
            // convert the body map to JSON and sends it back to the client
            mapper.writeValue(response.getOutputStream(),body);
    }
}

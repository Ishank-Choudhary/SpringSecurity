package com.security.securityDemo.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*AuthTokenFilter is a custom security filter that runs before every API request.
Its job:
➡️ Extract the JWT from the request
➡️ Validate it
➡️ Set the authenticated user in Spring Security’s context */

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserDetailsService userDetailsService;
    //Logger object
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
                logger.debug("AuthTokenFilter called for URI: {}",request.getRequestURI());
                try{
                    String jwt = parseJwt(request);
                    if(jwt!=null && jwtUtil.validateJwtToken(jwt)){
                        String username = jwtUtil.getUsernameFromJwtToken(jwt); // extract the username from the token
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username); // fetch that username from the db (Fetches user’s roles, password, etc.)
                        // I’ve already checked the JWT. This user is valid. Please consider them authenticated
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails,null,userDetails.getAuthorities()
                        );
                        /* This adds extra metadata about the request — for example:
                        The user’s IP address
                        The session ID
                        The browser info (if applicable)
                        //These details are optional but useful for logging or advanced security checks(like detecting logins from multiple IPs)*/
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        // this tells spring security, this request belongs to this user. You can now allow access to their authorized endpoints.
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                        logger.debug("Roles from JWt: {}",userDetails.getAuthorities());
                    }
                }catch (Exception e){
                    logger.error("Cannot set user authentication: {}",e);
                }
                //if it found the jwt successfully then it will send that call to the controller.
                filterChain.doFilter(request,response);
    }

    // This will extract the token from the 'Authorization' header
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtil.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}",jwt);
        return jwt;
    }
}

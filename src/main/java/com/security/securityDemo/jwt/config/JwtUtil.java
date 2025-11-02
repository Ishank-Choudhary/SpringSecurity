package com.security.securityDemo.jwt.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.security.Key;

// After the username and password are authenticated then this class will generate the token

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${spring.app.jwtExpiration}")
    private int jwtExpiration;
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    //Getting jwt from header(we have this in the postman)
    public String getJwtFromHeader(HttpServletRequest httpServletRequest){
        String bearerToken = httpServletRequest.getHeader("Authorization"); // this we will write in the postman header key
        logger.debug("Authorization Header: {}",bearerToken);
        if(bearerToken!=null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7); // it will remove the bearer prefix
        }
        return null;
    }

    //Generating token from username
    public String generateTokenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration*1000L)) // token will be having some expiration as well
                .signWith(key()) // we are signing that token with a key
                .compact();
    }

    //Get username from jwt token
    public String getUsernameFromJwtToken(String token){
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    //Generate signing key
    public Key key(){
        return Keys.hmacShaKeyFor(
                jwtSecret.getBytes(StandardCharsets.UTF_8)
        );
    }

    //validating jwt token
    public boolean validateJwtToken(String authtoken){
        try{
            System.out.println("Validate");
            Jwts.parserBuilder()
                    .setSigningKey((SecretKey) key())
                    .build()
                    .parseClaimsJws(authtoken);
            return true;
        }catch (MalformedJwtException exception){
            logger.error("Invalid JWT token: {}", exception.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("JWT token us expired: {}",e.getMessage());
        }
        return false;
    }
}

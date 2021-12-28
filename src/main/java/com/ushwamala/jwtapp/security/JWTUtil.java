package com.ushwamala.jwtapp.security;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JWTUtil {

    @Value("${jwt_secret}")
    private String secret;

    final String issuer = "jwt-app-ushwamala.com";
    final String subject = "User Details";
    final String claim = "email";

    public String generateToken(String email) throws IllegalArgumentException, JWTCreationException {

        return JWT.create()
                .withSubject(subject)
                .withClaim(claim, email)
                .withIssuedAt(new Date())
                .withIssuer(issuer)
                .sign(Algorithm.HMAC256(secret));
    }

    public String validateTokenAndRetrieveSubject(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
                .withSubject(subject)
                .withIssuer(issuer)
                .withSubject(subject)
                .build();
        DecodedJWT jwt = verifier.verify(token);
        return jwt.getClaim(claim).asString();
    }
}

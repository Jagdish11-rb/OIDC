package org.example.oidclogin;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 15; // 15 minutes
    private static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24; // 24 hours

    public static String generateAccessToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(SECRET_KEY)
                .compact();
    }

    public static String generateRefreshToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(SECRET_KEY)
                .compact();
    }

    public static String validateToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}

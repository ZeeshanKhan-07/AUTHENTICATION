package com.auth.authentication.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth.authentication.entity.Role;
import com.auth.authentication.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Service
public class JwtService {

    private final SecretKey key;

    private final long accessTokenExpiration; // in seconds

    private final long refreshTokenExpiration; // in seconds

    private final String jwtIssuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secretKey,
            @Value("${security.jwt.access-ttl-seconds}") long accessTokenExpiration,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTokenExpiration,
            @Value("${security.jwt.issuer}") String jwtIssuer) {

        if (secretKey == null || secretKey.length() < 64) {
            throw new IllegalArgumentException("Invalid secret key");
        }

        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.jwtIssuer = jwtIssuer;
    }

    // generate token
    public String generateAccessToken(User user) {
        Instant now = Instant.now();

        List<String> roles = user.getRoles() == null ? List.of() : user.getRoles().stream().map(Role::getName).toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getId().toString())
                .issuer(jwtIssuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenExpiration)))
                .claims(Map.of(
                        "email", user.getEmail(),
                        "roles", roles,
                        "typ", "access"))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // generate refresh token
    public String generateRefreshToken(User user, String jti) {
        Instant now = Instant.now();

        return Jwts.builder()
                .id(jti)
                .subject(user.getId().toString())
                .issuer(jwtIssuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(refreshTokenExpiration)))
                .claim("typ", "refresh")
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // parse token and validate
    public Jws<Claims> parse(String token) {
        try {
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
        } catch (Exception e) {
            throw new RuntimeException("Invalid token", e);
        }
    }

    public boolean isAccessToken(String token) {
        Claims c = parse(token).getPayload();
        return "access".equals(c.get("typ"));
    }

    public boolean isRefreshToken(String token) {
        Claims c = parse(token).getPayload();
        return "refresh".equals(c.get("typ"));
    }

    public UUID getUserId(String token) {
        Claims c = parse(token).getPayload();
        return UUID.fromString(c.getSubject());
    }

    public String getJti(String token) {
        Claims c = parse(token).getPayload();
        return c.getId();
    }

}

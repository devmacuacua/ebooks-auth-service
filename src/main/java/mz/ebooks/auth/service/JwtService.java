package mz.ebooks.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    private static final String BLACKLIST_PREFIX = "blacklist:";

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiry-ms}")
    private long accessTokenExpiryMs;

    private final RedisTemplate<String, String> redisTemplate;

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generate a signed JWT access token with userId, email, name and role claims.
     */
    public String generateAccessToken(String userId, String email, String name, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiryMs);

        return Jwts.builder()
                .subject(userId)
                .claim("email", email)
                .claim("name", name)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Generate a random UUID string to be used as a refresh token.
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Parse and validate a JWT token, returning its Claims.
     * Throws JwtException if invalid or expired.
     */
    public Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extract the userId (subject) from a JWT token.
     */
    public String getUserIdFromToken(String token) {
        return validateToken(token).getSubject();
    }

    /**
     * Check if an access token has been blacklisted in Redis.
     */
    public boolean isTokenBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        Boolean exists = redisTemplate.hasKey(key);
        return Boolean.TRUE.equals(exists);
    }

    /**
     * Blacklist a token in Redis with the given TTL in milliseconds.
     */
    public void blacklistToken(String token, long ttlMs) {
        if (ttlMs <= 0) {
            return;
        }
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.opsForValue().set(key, "1", ttlMs, TimeUnit.MILLISECONDS);
        log.debug("Token blacklisted with TTL {}ms", ttlMs);
    }

    /**
     * Returns the remaining validity of the token in milliseconds.
     * Returns 0 if the token is already expired or invalid.
     */
    public long getRemainingTtlMs(String token) {
        try {
            Claims claims = validateToken(token);
            long expiryMs = claims.getExpiration().getTime();
            long now = System.currentTimeMillis();
            return Math.max(0, expiryMs - now);
        } catch (JwtException e) {
            return 0;
        }
    }
}

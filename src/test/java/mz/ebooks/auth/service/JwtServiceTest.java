package mz.ebooks.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private static final String SECRET = "test-jwt-secret-that-is-at-least-32-bytes-long!!";
    private static final long EXPIRY_MS = 3_600_000L; // 1h

    @Mock RedisTemplate<String, String> redisTemplate;
    @Mock ValueOperations<String, String> valueOps;

    @InjectMocks JwtService jwtService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtService, "jwtSecret", SECRET);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiryMs", EXPIRY_MS);
    }

    // ── generateAccessToken ────────────────────────────────────────────────────

    @Test
    void generateAccessToken_containsExpectedClaims() {
        String token = jwtService.generateAccessToken("user-123", "user@test.com", "Test User", "CUSTOMER");

        Claims claims = parseToken(token);
        assertThat(claims.getSubject()).isEqualTo("user-123");
        assertThat(claims.get("email", String.class)).isEqualTo("user@test.com");
        assertThat(claims.get("name", String.class)).isEqualTo("Test User");
        assertThat(claims.get("role", String.class)).isEqualTo("CUSTOMER");
    }

    @Test
    void generateAccessToken_expiresAfterConfiguredDuration() {
        long before = System.currentTimeMillis();
        String token = jwtService.generateAccessToken("u1", "e@test.com", "User", "CUSTOMER");
        long after = System.currentTimeMillis();

        Claims claims = parseToken(token);
        long expMs = claims.getExpiration().getTime();
        assertThat(expMs).isBetween(before + EXPIRY_MS - 1000, after + EXPIRY_MS + 1000);
    }

    // ── generateRefreshToken ──────────────────────────────────────────────────

    @Test
    void generateRefreshToken_isValidUuid() {
        String token = jwtService.generateRefreshToken();
        assertThat(UUID.fromString(token)).isNotNull();
    }

    @Test
    void generateRefreshToken_isUnique() {
        String t1 = jwtService.generateRefreshToken();
        String t2 = jwtService.generateRefreshToken();
        assertThat(t1).isNotEqualTo(t2);
    }

    // ── validateToken ─────────────────────────────────────────────────────────

    @Test
    void validateToken_returnsClaims_forValidToken() {
        String token = jwtService.generateAccessToken("u1", "e@test.com", "User", "ADMIN");
        Claims claims = jwtService.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo("u1");
    }

    @Test
    void validateToken_throwsJwtException_forTamperedToken() {
        String token = jwtService.generateAccessToken("u1", "e@test.com", "User", "CUSTOMER");
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";

        assertThatThrownBy(() -> jwtService.validateToken(tampered))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void validateToken_throwsJwtException_forExpiredToken() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String expired = Jwts.builder()
                .subject("u-expired")
                .expiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();

        assertThatThrownBy(() -> jwtService.validateToken(expired))
                .isInstanceOf(JwtException.class);
    }

    // ── getRemainingTtlMs ─────────────────────────────────────────────────────

    @Test
    void getRemainingTtlMs_returnsPositiveValue_forFreshToken() {
        String token = jwtService.generateAccessToken("u1", "e@test.com", "User", "CUSTOMER");
        long ttl = jwtService.getRemainingTtlMs(token);
        assertThat(ttl).isPositive().isLessThanOrEqualTo(EXPIRY_MS);
    }

    @Test
    void getRemainingTtlMs_returnsZero_forExpiredToken() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String expired = Jwts.builder()
                .subject("u-exp")
                .expiration(new Date(System.currentTimeMillis() - 1000))
                .signWith(key)
                .compact();

        long ttl = jwtService.getRemainingTtlMs(expired);
        assertThat(ttl).isZero();
    }

    // ── blacklistToken / isTokenBlacklisted ───────────────────────────────────

    @Test
    void blacklistToken_storesKeyInRedis() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);

        jwtService.blacklistToken("some.jwt.token", 30_000L);

        verify(valueOps).set(eq("blacklist:some.jwt.token"), eq("1"), eq(30_000L), any());
    }

    @Test
    void blacklistToken_doesNothing_whenTtlIsZero() {
        jwtService.blacklistToken("token", 0L);
        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    void isTokenBlacklisted_returnsTrue_whenKeyExistsInRedis() {
        when(redisTemplate.hasKey("blacklist:token-x")).thenReturn(true);
        assertThat(jwtService.isTokenBlacklisted("token-x")).isTrue();
    }

    @Test
    void isTokenBlacklisted_returnsFalse_whenKeyNotInRedis() {
        when(redisTemplate.hasKey(anyString())).thenReturn(false);
        assertThat(jwtService.isTokenBlacklisted("token-y")).isFalse();
    }

    // ── helper ────────────────────────────────────────────────────────────────

    private Claims parseToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }
}

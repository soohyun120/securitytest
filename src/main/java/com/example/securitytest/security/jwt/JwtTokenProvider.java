package com.example.securitytest.security.jwt;

import com.example.securitytest.security.UserDetailsImpl;
import com.example.securitytest.web.User;
import com.example.securitytest.web.redis.RedisService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import static com.example.securitytest.security.jwt.JwtProperties.*;

/**
 * JWT Token 생성, 검증, 활용
 */
@Component
@Slf4j
public class JwtTokenProvider {

    private final UserDetailsService userDetailsService;
    private final Key key;
    private final RedisService redisService;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secretKey,
            UserDetailsService userDetailsService,
            RedisService redisService) {

        byte[] KeyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        this.key = Keys.hmacShaKeyFor(KeyBytes);
        this.userDetailsService = userDetailsService;
        this.redisService = redisService;
    }

    /**
     * Access Token 생성 후 반환
     */
    public String generateAccessToken(User user) {
        Date now = new Date();
        return Jwts.builder()
                .setHeaderParam("typ", "ACCESS_TOKEN")
                .setHeaderParam("alg", "HS512")
                .setSubject(user.getUsername())
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + ACCESS_TOKEN_VALID_TIME))
                .claim("role", user.getRole())
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Refresh Token 생성 후 반환
     */
    public String generateRefreshToken(User user) {
        Date now = new Date();
        return Jwts.builder()
                .setHeaderParam("typ", "REFRESH_TOKEN")
                .setHeaderParam("alg", "HS512")
                .setSubject(user.getUsername())
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + REFRESH_TOKEN_VALID_TIME))
                .claim("role", user.getRole())
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * JWT Token 에 담긴 유저 정보를 DB 에 검색
     * @return SecurityContextHolder 에 담을 Authentication 객체
     */
    public Authentication getAuthentication(String token) {
        UserDetailsImpl userDetails =
                (UserDetailsImpl) userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());
    }

    /**
     * JWT Token 에서 유저 정보 추출
     */
    private String getUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * header 에서 JWT Token 받아오기
     */
    public String resolveToken(HttpServletRequest request) {
        String header = request.getHeader(HEADER_STRING);
        if (header != null && header.startsWith(TOKEN_PREFIX))
            return header.replace(TOKEN_PREFIX, "");
        return null;
    }

    /**
     * JWT Token 검증
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = parseClaims(token);
            return !claims.getExpiration().before(new Date());

        } catch (SignatureException e) {
            log.error("Invalid JWT signature", e);
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token", e);
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired", e);
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported", e);
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty", e);
        }
        return false;
    }

    /**
     * 토큰 만료시간
     */
    public long getExpiration(String token) {
        Date expiration = parseClaims(token).getExpiration();
        long currentTime = new Date().getTime();

        return expiration.getTime() - currentTime;
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

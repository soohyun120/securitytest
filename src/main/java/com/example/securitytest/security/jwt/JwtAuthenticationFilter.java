package com.example.securitytest.security.jwt;

import com.example.securitytest.exception.ErrorCode;
import com.example.securitytest.exception.UserException;
import com.example.securitytest.web.redis.RedisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.securitytest.exception.ErrorCode.*;
import static com.example.securitytest.web.redis.RedisKey.BLACKLIST;


/**
 * JWT Token 의 유효성을 검증하는 필터
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = jwtTokenProvider.resolveToken(request);

        //Access Token 유효 검증
        if (accessToken != null && jwtTokenProvider.validateToken(accessToken)) {

            //logout 검증
            checkLogout(accessToken);

            Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }

    private void checkLogout(String accessToken) {
        String isLogout = redisService.getData(BLACKLIST.getKey() + accessToken);

        if (StringUtils.hasText(isLogout))
            throw new UserException(NO_LOGIN);
    }
}

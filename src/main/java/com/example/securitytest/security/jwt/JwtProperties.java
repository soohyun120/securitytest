package com.example.securitytest.security.jwt;

public interface JwtProperties {
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
    Long ACCESS_TOKEN_VALID_TIME = 30 * 60 * 1000L; //30분
    Long REFRESH_TOKEN_VALID_TIME = 60 * 60 * 24 * 14 * 1000L; //2주
}

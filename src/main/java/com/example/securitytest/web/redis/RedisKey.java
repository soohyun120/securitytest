package com.example.securitytest.web.redis;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 이메일 인증      key(EMAILAUTH_email),         value(UUID)
 * Refresh Token  key(REFRESH_username),        value(refresh Token)
 * BlackList      key(BLACKLIST_access Token),  value(access Token)
 */

@Getter
@AllArgsConstructor
public enum RedisKey {
    EMAILAUTH("EMAILAUTH_"), REFRESH("REFRESH_"), BLACKLIST("BLACKLIST_");

    private String key;
}

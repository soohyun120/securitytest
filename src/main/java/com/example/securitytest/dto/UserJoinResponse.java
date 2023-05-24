package com.example.securitytest.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserJoinResponse {
    private String authKey;
    private boolean expired;
}

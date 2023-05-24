package com.example.securitytest.dto;

import lombok.Data;

@Data
public class ReissueRequest {
    private String username;
    private String refreshToken;
}

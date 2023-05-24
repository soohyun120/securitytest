package com.example.securitytest.dto;

import lombok.Data;

@Data
public class UpdatePasswordRequest {
    private String currentPw;
    private String newPw;
}

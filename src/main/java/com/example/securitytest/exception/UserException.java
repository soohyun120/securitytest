package com.example.securitytest.exception;

import lombok.Getter;

@Getter
public class UserException extends RuntimeException {

    private ErrorCode errorCode;

    public UserException(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }
}

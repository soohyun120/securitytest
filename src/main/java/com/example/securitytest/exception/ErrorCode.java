package com.example.securitytest.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    ALREADY_EXIST_USER(HttpStatus.BAD_REQUEST, "이미 존재하는 아이디입니다."),
    WRONG_PASSWORD(HttpStatus.BAD_REQUEST, "비밀번호가 일치하지 않습니다."),
    NO_USER(HttpStatus.NOT_FOUND, "존재하지 않는 사용자입니다."),
    NO_LOGIN(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다."),

    NO_CERTIFICATION(HttpStatus.UNAUTHORIZED, "인증되지 않았습니다."),

    INVALID_ACCESS_TOKEN(HttpStatus.BAD_REQUEST, "유효하지 않은 엑세스 토큰입니다."),
    INVALID_REFRESH_TOKEN(HttpStatus.BAD_REQUEST, "유효하지 않은 리프레시 토큰입니다."),
    NO_REFRESH_TOKEN(HttpStatus.NOT_FOUND, "존재하지 않는 리프레시 토큰입니다."),
    NO_AUTH_TOKEN(HttpStatus.NOT_FOUND, "존재하지 않는 인증 토큰입니다.")
    ;

    private final HttpStatus httpStatus;
    private final String message;
}

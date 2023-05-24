package com.example.securitytest.web;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "USER_ID")
    private Long id;

    @Column(nullable = false)
    private String username; //학번

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email; //학교 이메일

    @Column(nullable = false)
    private String name; //이름

    @Enumerated(EnumType.STRING)
    private UserRole role;

    @Column(nullable = false)
    private boolean authStatus;

    @Builder
    public User(String username, String password, String email, String name, boolean authStatus) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.name = name;
        this.authStatus = authStatus;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }

    /**
     * 이메일 인증 진행
     */
    public void setAuthStatus() {
        this.authStatus = true;
    }

    /**
     * 패스워드 암호화
     */
    public void encodePassword(PasswordEncoder passwordEncoder) {
        this.password = passwordEncoder.encode(password);
    }

    /**
     * 비밀번호 업데이트
     */
    public void updatePw(String newPw) {
        this.password = newPw;
    }
}

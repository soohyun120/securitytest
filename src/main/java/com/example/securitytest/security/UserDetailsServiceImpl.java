package com.example.securitytest.security;

import com.example.securitytest.exception.UserException;
import com.example.securitytest.web.User;
import com.example.securitytest.web.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static com.example.securitytest.exception.ErrorCode.NO_USER;

/**
 * AuthenticationProvider vs UserDetailsService
 **/

/**
 * AuthenticationProvider
 * - UsernamePasswordToken 전달받아 인증 과정 수행
 * - DB 에서 비밀번호 일치 여부 작업을 직접 구현하고 싶으면 AuthenticationProvider 커스텀 구현
 * - UserDetailsService 를 사용할 경우 자동으로 DaoAuthenticationProvider 객체 사용
 *
 * 인증 과정
 * 1.username 으로 DB 에서 아이디 조회
 * 2.UserDetailsService 에서 아이디를 기반으로 데이터 조회
 * 3.조회된 데이터를 AuthenticationProvider 에 반환
 * 4.AuthenticationProvider 는 반환된 정보와 입력받은 비밀번호의 일치 여부 확인
 * 5.일치하면 인증된 토큰 생성 후 AuthenticationManager 에 반환
 **/

/**
 * UserDetailsService
 * - 사용자의 정보를 가져오는 인터페이스
 * - 아이디를 기반으로 DB 조회
 * - AuthenticationProvider 에 조회된 데이터를 반환
 **/

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new UserException(NO_USER));
        return new UserDetailsImpl(user);
    }
}

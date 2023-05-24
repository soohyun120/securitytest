package com.example.securitytest.config;

import com.example.securitytest.security.jwt.JwtAccessDeniedHandler;
import com.example.securitytest.security.jwt.JwtAuthenticationEntryPoint;
import com.example.securitytest.security.jwt.JwtAuthenticationFilter;
import com.example.securitytest.security.jwt.JwtTokenProvider;
import com.example.securitytest.web.redis.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity //SecurityConfig.class 를 Spring Filter Chain 에 등록
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisService redisService;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .httpBasic().disable()  // rest api 이므로 기본설정 미사용
                .csrf().disable()   //rest api 이므로 csrf 보안 미사용
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //jwt로 인증하므로 세션 미사용

                .and()

                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/user/join").permitAll()
                        .requestMatchers("/api/user/joinConfirm").permitAll()
                        .requestMatchers("/api/user/login").permitAll()
                        .requestMatchers("/api/user/reissue").permitAll()
                        .requestMatchers("/api/user/password").permitAll()
                        .requestMatchers("/api/exception/**").permitAll()
                        .anyRequest().authenticated()
                )

                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and()

                .build();
    }
}

package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.config.jwt.JwtAuthenticationFilter;
import com.example.springsecurityjwt.filter.MyFilter01;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity   // 스프링 시큐리티 필터가 스프링 필터 체인에 등록됨
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.addFilterBefore(new MyFilter01(), SecurityContextPersistenceFilter.class);   // MyFilter01 필터 등록

        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)   // 세션을 사용하지 않겠다는 설정
                .and()
                .addFilter(corsFilter)   // corsFilter 등록(인증이 필요한 요청도 허용) <-> @CrossOrigin은 인증이 필요없는 요청만 허용
                .formLogin().disable()   // 별도의 로그인 페이지 사용하지 않음
                .httpBasic().disable()   // 기존의 http 방식 사용하지 않음
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))   // JwtAuthenticationFilter 필터 등록 (authenticationManager는 필수)
                .authorizeRequests()
                .antMatchers("/api/v1/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**").access(" hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}



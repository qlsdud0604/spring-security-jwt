package com.example.springsecurityjwt.config;

import com.example.springsecurityjwt.filter.MyFilter02;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter02> filter02() {
        FilterRegistrationBean<MyFilter02> registrationBean = new FilterRegistrationBean<>(new MyFilter02());   // MyFilter02 필터 등록

        registrationBean.addUrlPatterns("/*");   // 모든 url에 대해서 필터를 설정
        registrationBean.setOrder(0);   // 필터 중에서 가장 먼저 실행(낮은 번호를 가질 수록 우선순위 높음)

        return registrationBean;
    }
}

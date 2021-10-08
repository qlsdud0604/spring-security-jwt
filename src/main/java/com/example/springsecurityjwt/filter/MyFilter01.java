package com.example.springsecurityjwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter01 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("필터01");
        filterChain.doFilter(servletRequest, servletResponse);
    }
}

package com.example.springsecurityjwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter01 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;   // HttpServletRequest 타입으로 다운 캐스팅
        HttpServletResponse res = (HttpServletResponse) servletResponse;   // HttpServletRequest 타입으로 다운 캐스팅

        /** POST 요청일 경우에만 동작 */
        if (req.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            /* header의 내용이 "test token"인 경우 -> 정상 처리*/
            if (headerAuth.equals("test token")) {
                filterChain.doFilter(req, res);
            }
            /* header의 내용이 "test token"이 아닌 경우 -> 실패 처리 */
            else {
                PrintWriter printWriter = res.getWriter();
                printWriter.println("인증에 실패하였습니다.");
            }
        }
    }
}

// 1. id, pw가 정상적으로 전송되고 로그인이 완료되면 토큰을 만들어주고 클라이언트 측으로 응답을 해준다.
// 2. 클라이언트 측은 다음 요청부터 header의 Authorization의 value 값으로 토큰을 가지고 요청을 한다.
// 3. 토큰이 넘어오면 서버측에서는 해당 토큰이 자신이 만든 토큰인지만 검증하면 된다.



package com.example.idpdemo.controller;

import com.example.idpdemo.domain.User;
import com.example.idpdemo.filters.IdpAuthRequestFilter;
import com.example.idpdemo.filters.IdpLoginFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        System.out.println("!!!!!LOGIN");
        return "/loginForm";
    }

    @PostMapping("/login")
    public String loginProcess(HttpServletRequest request, HttpServletResponse response) {
        User user = new User();
        user.setLoginId("admin");
        request.getSession().setAttribute("user", user);
        HttpSessionRequestCache cache = new HttpSessionRequestCache();
        SavedRequest savedRequest = cache.getRequest(request, response);
        if (Objects.nonNull(savedRequest)) {
            System.out.println(savedRequest.getRedirectUrl());
            try {
                response.sendRedirect(savedRequest.getRedirectUrl());
                return null;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        }
        return "/successForm";
    }
}

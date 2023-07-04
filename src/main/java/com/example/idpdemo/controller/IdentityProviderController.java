package com.example.idpdemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class IdentityProviderController {
    @RequestMapping(value = {"/"})
    public String selectProvider() {
        return "redirect:/saml/idp/select";
    }

}

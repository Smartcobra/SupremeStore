package com.supremestore.userresources.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
//@RequestMapping("/v1/api/user")
public class UserController {


//    @GetMapping("/username")
//    public String demo(){
//        return "i am user";
//    }

    @GetMapping(value = "/messages")
    public String currentUserName(Principal principal) {
     return principal.getName();
        //return "jitu";
    }

    ///localhost:9100/oauth/authorize?client_id=client&scope=openid&redirect_uri=http://127.0.0.1:8080/authorized

}

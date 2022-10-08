package com.supremestore.authservice.service;

import com.supremestore.authservice.entity.CustomUser;
import com.supremestore.authservice.repo.CustomUserRepo;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@AllArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final CustomUserRepo customUserRepo;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(customUserRepo.findAll());
        //System.out.println("---------"+customUserRepo.findAll());
       // System.out.println("Roles-----"+roleRepo.findAll());
        Optional<CustomUser> user = customUserRepo.findByUsername(username);

       /// user.ifPresent(customUser -> System.out.println("user name-------" + customUser.getUsername()));


        if (user.isEmpty()) {
            throw new UsernameNotFoundException("No User Found");
        }


        return new CustomUserDetail(user.get());
    }

//    private Collection<? extends GrantedAuthority> getAuthorities(List<String> roles) {
//        List<GrantedAuthority> authorities = new ArrayList<>();
//        for (String role : roles) {
//            authorities.add(new SimpleGrantedAuthority(role));
//        }
//        return authorities;
//    }
}

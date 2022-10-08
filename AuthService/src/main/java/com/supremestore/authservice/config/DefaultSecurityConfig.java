package com.supremestore.authservice.config;

import com.supremestore.authservice.service.CustomAuthenticationProvider;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
//@EnableWebSecurity
@AllArgsConstructor
public class DefaultSecurityConfig {

    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final CORSCustomizer corsCustomizer;


    /*
     *
     * *****************************   this method used for form login  ***********************
     * */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        corsCustomizer.corsCustomizer(http);
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                                .antMatchers("/webjars/**")
                                .permitAll()
                                .anyRequest().authenticated())
                ///  .formLogin(withDefaults());
                .formLogin()
                .loginPage("/login")
                .successHandler(new RefererRedirectionAuthenticationSuccessHandler())
                .defaultSuccessUrl("http://127.0.0.1:3000/authorized").permitAll()
                .and()
                .csrf().disable();
        ;
        return http.build();
    }
    /*
     *       *********************use this method for HTTP  *******************************
     * */
/*    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        corsCustomizer.corsCustomizer(http);
        return http.csrf().disable().authorizeRequests().antMatchers("/api/**").permitAll().anyRequest().authenticated()
                .and().build();
    }*/


    /*
     *            In memory check
     * */
//    @Bean
//    UserDetailsService users(){
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user1")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user);
//    }

    @Autowired
    public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder.authenticationProvider(customAuthenticationProvider);
    }
}

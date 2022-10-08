package com.supremestore.authservice.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;



@Configuration
public class RefererRedirectionAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public RefererRedirectionAuthenticationSuccessHandler() {
            super();
            setUseReferer(true);
        }
}

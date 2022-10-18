package com.supremestore.userresources;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@SpringBootApplication
@EnableEurekaClient
public class UserResourcesApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserResourcesApplication.class, args);
    }

}

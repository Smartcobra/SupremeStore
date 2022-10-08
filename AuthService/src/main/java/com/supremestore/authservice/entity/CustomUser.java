package com.supremestore.authservice.entity;


import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@Component
@ToString
@Document(collection = "users")
public class CustomUser {



    @Id
    private String uid;

    @NonNull
    private String username;
    @NonNull
    private String password;

    @NonNull
    private String email;

   // @NonNull
     @DBRef
    //@DocumentReference // role commimg null
    private Set<Roles> roles= new HashSet<>();

//    public CustomUser(String uid, @NonNull String username, @NonNull String password, @NonNull String email) {
//        this.uid = uid;
//        this.username = username;
//        this.password = password;
//        this.email = email;
//    }


//    public CustomUser(String uid, @NonNull String username, @NonNull String password, @NonNull String email, Set<Roles> roles) {
//        this.username = username;
//        this.password = password;
//        this.email = email;
//        this.roles = roles;
//    }

    public CustomUser(@NonNull String username, @NonNull String password, @NonNull String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }
}

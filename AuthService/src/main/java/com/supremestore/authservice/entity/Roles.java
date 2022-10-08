package com.supremestore.authservice.entity;


import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.stereotype.Component;
@Setter
@Getter
@Component
@ToString
@NoArgsConstructor
@Document(collection = "roles")
public class Roles {

    @Id
    private String id;
    private ERoles name;

    public Roles(ERoles name){
        this.name=name;
    }

}

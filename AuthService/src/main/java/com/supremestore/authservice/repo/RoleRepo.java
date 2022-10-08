package com.supremestore.authservice.repo;

import com.supremestore.authservice.entity.ERoles;
import com.supremestore.authservice.entity.Roles;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepo extends MongoRepository<Roles,String> {
    Optional<Roles> findByName(ERoles name);
}

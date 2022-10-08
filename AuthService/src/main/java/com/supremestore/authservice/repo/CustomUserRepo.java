package com.supremestore.authservice.repo;

import com.supremestore.authservice.entity.CustomUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomUserRepo extends MongoRepository<CustomUser,String> {
    Optional<CustomUser> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);

}

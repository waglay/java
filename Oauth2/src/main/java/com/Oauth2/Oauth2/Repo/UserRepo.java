package com.Oauth2.Oauth2.Repo;

import com.Oauth2.Oauth2.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User,String> {

Optional<User> findByUsername(String username);
}

package com.Oauth2.Oauth2.Impl;

import com.Oauth2.Oauth2.Dto.UserDto;
import com.Oauth2.Oauth2.Entity.User;
import com.Oauth2.Oauth2.Repo.UserRepo;
import com.Oauth2.Oauth2.Service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepo userRepo;

    private final PasswordEncoder passwordEncoder;
private final ModelMapper mapper;
    public UserServiceImpl(UserRepo userRepo,ModelMapper mapper, PasswordEncoder passwordEncoder) {
        this.userRepo = userRepo;
        this.mapper = mapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDto createUser(UserDto userDto) {
        User user = mapper.map(userDto, User.class);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        User save = userRepo.save(user);
        return mapper.map(save,UserDto.class);
    }

    @Override
    public List<UserDto> displayUSer() {
        List<User> user = userRepo.findAll();
        return user.stream().map(e->mapper.map(e,UserDto.class)).collect(Collectors.toList());
    }
}

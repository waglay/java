package com.Oauth2.Oauth2.Service;

import com.Oauth2.Oauth2.Dto.UserDto;

import java.util.List;

public interface UserService {
//create user
UserDto createUser(UserDto userDto);

//display user
List<UserDto> displayUSer();
}

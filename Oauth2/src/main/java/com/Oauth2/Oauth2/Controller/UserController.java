package com.Oauth2.Oauth2.Controller;

import com.Oauth2.Oauth2.Dto.UserDto;
import com.Oauth2.Oauth2.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto){
        UserDto user = userService.createUser(userDto);
        return ResponseEntity.ok(user);
    }


}

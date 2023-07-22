package com.Oauth2.Oauth2.Controller;

import com.Oauth2.Oauth2.Dto.UserDto;
import com.Oauth2.Oauth2.Service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
@RestController
@RequestMapping("/view")
public class Controller {
    private final
    UserService userService;

    public Controller(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> display(){
        List<UserDto> userDtos = userService.displayUSer();
        return ResponseEntity.ok(userDtos);
    }
}

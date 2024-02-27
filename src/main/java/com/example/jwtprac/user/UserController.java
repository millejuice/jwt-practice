package com.example.jwtprac.user;

import com.example.jwtprac.jwt.JwtToken;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/login")
    public JwtToken signin(@RequestBody UserRequestDto.SignInRequest request){
        String username = request.getUsername();
        String password = request.getPassword();
        return userService.signin(username, password);
    }

    @PostMapping("/user/test")
    public String test(){
        return "test";
    }
}

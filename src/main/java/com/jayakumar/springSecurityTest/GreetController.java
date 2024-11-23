package com.jayakumar.springSecurityTest;


import com.jayakumar.springSecurityTest.jwt.JwtUtils;
import com.jayakumar.springSecurityTest.jwt.LoginRequest;
import com.jayakumar.springSecurityTest.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;










    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest)
    {
        Authentication authentication;

        try{
            authentication= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));

        }
        catch(AuthenticationException exception){
            Map<String,Object> map=new HashMap<>();
            map.put("message","Bad Credentials");
            map.put("status",false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);

    }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails= (UserDetails) authentication.getPrincipal();
        String jwtToken=jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles=userDetails.getAuthorities().stream().map(item->item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse loginResponse=new LoginResponse(jwtToken,userDetails.getUsername(),roles);

        return ResponseEntity.ok(loginResponse);
    }


    @GetMapping("/")
    public String greet()
    {
        return "hello guys";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint()
    {
        return "user endpoint";
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint()
    {
        return "admin endpoint";
    }

}

package com.security.databaseservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/consumer")
public class databaseController {
    @GetMapping("/message")
    public ResponseEntity<String> message() {
        return ResponseEntity.ok("This is database service");
    }
}


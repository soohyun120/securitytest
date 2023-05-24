package com.example.securitytest.exception;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/exception")
public class ExceptionController {

        @GetMapping("/entry")
        public void entryPointException() {
                throw new AuthenticationEntryPointException();
        }

        @GetMapping("/denied")
        public void accessDeniedException() {
                throw new AccessDeniedException();
        }
}

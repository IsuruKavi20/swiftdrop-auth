package com.swiftdrop.auth.common.error;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Replaces Spring Boot's default /error page (which returns its own JSON including the path)
 * for errors raised by the servlet container itself, outside Spring MVC.
 */
@RestController
public class ProblemErrorController implements ErrorController {

    @RequestMapping("/error")
    ResponseEntity<ProblemDetail> error(HttpServletRequest request) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        ErrorCode code = ErrorCode.forStatus(status instanceof Integer value ? value : 500);
        return ResponseEntity.status(code.status()).body(ProblemDetails.of(code));
    }
}

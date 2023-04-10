package team24.security.configuration;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import team24.security.exceptions.*;

@ControllerAdvice
public class RuntimeErrorHandling {
    @ExceptionHandler(BaseException.class)
    public ResponseEntity<?> notFoundExceptionHandler(BaseException exception) {
        return new ResponseEntity<>(new ErrorResponse(exception.getMessage(), exception.getStatus()), exception.getStatus());
    }
}

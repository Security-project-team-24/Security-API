package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class VerificationFailedException extends BaseException {
    public VerificationFailedException(){
        super("Verification failed!", HttpStatus.CONFLICT);}
}

package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class CreateCertificateExtensionsException extends BaseException{
    
    public CreateCertificateExtensionsException() {
        super("Invalid Extensions for chosen issuer!", HttpStatus.CONFLICT);
    }
}

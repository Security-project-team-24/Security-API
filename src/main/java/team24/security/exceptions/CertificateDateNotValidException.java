package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class CertificateDateNotValidException extends BaseException {

    public CertificateDateNotValidException() {
        super("Certificate date not valid!", HttpStatus.BAD_REQUEST);
    }

}

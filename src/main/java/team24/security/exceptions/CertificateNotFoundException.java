package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class CertificateNotFoundException extends BaseException {

    public CertificateNotFoundException() {
        super("Certificate not found!", HttpStatus.NOT_FOUND);
    }
}

package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class NoPermissionToGenerateCertificateException extends BaseException {
    public NoPermissionToGenerateCertificateException() {
        super("No permission to generate certificate", HttpStatus.FORBIDDEN);
    }
}

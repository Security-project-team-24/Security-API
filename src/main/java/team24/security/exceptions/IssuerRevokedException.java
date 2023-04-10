package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class IssuerRevokedException extends BaseException {
    public IssuerRevokedException() {
        super("Issuer has been revoked!", HttpStatus.CONFLICT);
    }
}

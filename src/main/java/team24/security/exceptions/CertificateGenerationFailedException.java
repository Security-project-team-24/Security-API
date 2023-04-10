package team24.security.exceptions;

import org.springframework.http.HttpStatus;

public class CertificateGenerationFailedException extends BaseException {

    public CertificateGenerationFailedException() {
        super("Certificate generation failed!", HttpStatus.BAD_REQUEST);
    }
}

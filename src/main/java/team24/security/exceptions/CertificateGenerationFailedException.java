package team24.security.exceptions;

class CertificateGenerationFailedException extends RuntimeException {

    CertificateGenerationFailedException() {
        super("Certificate generation failed!");
    }
}

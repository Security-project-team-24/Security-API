package team24.security.exceptions;

public class CertificateNotFound extends RuntimeException {
    CertificateNotFound() {
        super("Certificate not found!");
    }
}

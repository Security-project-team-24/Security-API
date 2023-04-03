package team24.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import team24.security.model.Certificate;

import java.util.UUID;

public interface ICertificateRepository extends JpaRepository<Certificate, UUID> {
}

package team24.security.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import team24.security.model.Certificate;

import java.util.List;
import java.util.UUID;

public interface ICertificateRepository extends JpaRepository<Certificate, UUID> {
    Certificate findOneBySerialNumber(String issuerSerial);
    List<Certificate> findAllByIssuerSerial(String serialNumber);
    Page<Certificate> findAll(Pageable pageable);
}

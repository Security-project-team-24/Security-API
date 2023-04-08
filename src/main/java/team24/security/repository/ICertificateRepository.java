package team24.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import team24.security.model.Certificate;

import java.util.List;
import java.util.UUID;

public interface ICertificateRepository extends JpaRepository<Certificate, UUID> {
    Certificate findOneBySerialNumber(String issuerSerial);
    List<Certificate> findAllByIssuerSerial(String serialNumber);
    List<Certificate> findAll();
    @Query(value = "select * from certificate where keystore in ('intermediary.jks', 'root.jks') and revocation_status=false", nativeQuery = true)
    List<Certificate> findAllCAs();
}

package team24.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import team24.security.model.Keystore;

import java.util.UUID;

public interface IKeystoreRepository extends JpaRepository<Keystore, UUID> {

    Keystore findOneByName(String name);
}

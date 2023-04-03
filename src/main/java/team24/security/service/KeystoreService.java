package team24.security.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import team24.security.model.Keystore;
import team24.security.repository.IKeystoreRepository;

import java.util.UUID;

@Service
@AllArgsConstructor
public class KeystoreService {
    private IKeystoreRepository keystoreRepository;
    private EncryptionService encryptionService;

    public Keystore create(String name) {
        UUID generatedPassword = UUID.randomUUID();
        String password = encryptionService.encrypt(generatedPassword.toString());
        Keystore keystore = Keystore.builder()
                .name(name)
                .password(password)
                .build();
        keystore = keystoreRepository.save(keystore);
        return keystore;
    }

    public Keystore findById(UUID id) {
        return this.keystoreRepository
                .findById(id)
                .orElseThrow(() -> new RuntimeException("No keystore could be found!"));
    }

    public Keystore findOrCreate(String name) {
        Keystore store = findByName(name);
        if (store != null)
            return store;

        return create(name);
    }

    public Keystore findByName(String name) {
        return this.keystoreRepository.findOneByName(name);
    }
}

package team24.security.service;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import team24.security.model.Keystore;
import team24.security.repository.IKeystoreRepository;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

@Service
public class FileKeystoreService {
    private KeyStore keyStore;
    private String path;

    @Autowired
    private KeystoreService keystoreService;
    @Autowired
    private EncryptionService encryptionService;

    FileKeystoreService() {
        this.path = Dotenv.load().get("PATH_TO_KEYSTORES");
        try {
            keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (Exception e) {
            throw new RuntimeException("Something wrong with creating keystore!");
        }
    }

    public void saveKeyStore(String fileName) {
        try {
            Keystore store = keystoreService.findByName(fileName);
            if (store != null) {
                char[] password = encryptionService.decrypt(store.getPassword()).toCharArray();
                keyStore.store(new FileOutputStream(path + fileName + ".jks"), password);
                return;
            }

            throw new RuntimeException("File doesn't exist in database!");

        } catch (Exception e) {
            throw new RuntimeException("Something wrong with saving keystore!");
        }
    }

    public void loadKeyStore(String fileName) {
        try {
            Keystore store = keystoreService.findByName(fileName);

            if (store != null) {
                char[] password = encryptionService.decrypt(store.getPassword()).toCharArray();
                keyStore.load(new FileInputStream(fileName), password);
                return;
            }

            Keystore newKeystore = keystoreService.create(path);
            char[] password = encryptionService.decrypt(newKeystore.getPassword()).toCharArray();
            keyStore.load(null, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

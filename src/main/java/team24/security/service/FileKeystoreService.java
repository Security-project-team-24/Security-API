package team24.security.service;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import team24.security.model.Keystore;
import team24.security.repository.IKeystoreRepository;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
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

    public void findOrCreateKeystore(String fileName) {
        System.out.println(path);
        File file = new File(path, fileName);
        try {
            if (!file.exists()) {
                file.createNewFile();
            }
        } catch (IOException e) {
            // Handle the exception
            e.printStackTrace();
        }
    }

    public void save(String fileName) {
        try {
            Keystore store = keystoreService.findByName(fileName);
            if (store != null) {
                char[] password = encryptionService.decrypt(store.getPassword()).toCharArray();
                System.out.println(path + fileName);
                keyStore.store(new FileOutputStream(path + fileName), password);
                return;
            }

            throw new RuntimeException("File doesn't exist in database!");

        } catch (Exception e) {
            throw new RuntimeException("Something wrong with saving keystore!");
        }
    }

    public void load(String fileName) {
        try {
            Keystore store = keystoreService.findByName(fileName);

            if (store == null) {
                store = keystoreService.create(fileName);
            }
            char[] password = encryptionService.decrypt(store.getPassword()).toCharArray();

            if (fileExistsInDirectory(fileName)) {
                keyStore.load(new FileInputStream(path + fileName), password);
            } else {
                keyStore.load(null, password);
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void write(String alias, PrivateKey privateKey, char[] password, java.security.cert.Certificate certificate) {
        try {
            keyStore.setKeyEntry(alias, privateKey, password, new Certificate[]{certificate});
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private boolean fileExistsInDirectory(String fileName) {
        File directory = new File(path);
        if (!directory.isDirectory()) {
            // Path is not a directory
            return false;
        }
        File[] files = directory.listFiles();
        if (files == null) {
            // Directory is empty or an I/O error occurred
            return false;
        }
        for (File file : files) {
            if (file.isFile() && file.getName().equals(fileName)) {
                // File with given name found in directory
                return true;
            }
        }
        // File not found in directory
        return false;
    }

    public Certificate readCertificate(String keyStoreFile, String keyStorePass, String alias) {
        try {
            //kreiramo instancu KeyStore
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            //ucitavamo podatke
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(path + keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());

            if(ks.isKeyEntry(alias)) {
                Certificate cert = ks.getCertificate(alias);
                return cert;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}

package team24.security.service;

import lombok.AllArgsConstructor;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import team24.security.dto.CertificateRequestDto;
import team24.security.dto.KeyUsageDto;
import team24.security.dto.PageDto;
import team24.security.dto.RevocationDto;
import team24.security.exceptions.*;
import team24.security.model.Certificate;
import team24.security.model.Issuer;
import team24.security.model.Keystore;
import team24.security.model.Subject;
import team24.security.repository.ICertificateRepository;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
@AllArgsConstructor
public class CertificateService {

    private ICertificateRepository certificateRepository;
    private FileKeystoreService fileKeystoreService;
    private KeystoreService keystoreService;
    private EncryptionService encryptionService;

    private X509Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber, int usage, boolean isCA) {
        try {
            JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
            builder = builder.setProvider("BC");

            ContentSigner contentSigner = builder.build(issuer.getPrivateKey());
            X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuer.getX500Name(),
                    new BigInteger(serialNumber),
                    startDate,
                    endDate,
                    subject.getX500Name(),
                    subject.getPublicKey());
            
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            certGen.addExtension(Extension.basicConstraints,true,new BasicConstraints(isCA));
            certGen.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
            certGen.addExtension(Extension.subjectKeyIdentifier, true, extUtils.createSubjectKeyIdentifier(subject.getPublicKey()));
            certGen.addExtension(Extension.authorityKeyIdentifier, true, extUtils.createAuthorityKeyIdentifier(issuer.getPublicKey()));

            X509CertificateHolder certHolder = certGen.build(contentSigner);
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
            certConverter = certConverter.setProvider("BC");
            return certConverter.getCertificate(certHolder);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private Certificate create(Certificate certificate) {
        return certificateRepository.save(certificate);
    }

    public Certificate findById(UUID uuid) {
        return certificateRepository
                .findById(uuid)
                .orElseThrow(() -> new RuntimeException("Certificate doesn't exist!"));
    }

    public List<Certificate> findCertificateChain(String serialNumber) {
        return findCertificateChildren(serialNumber);
    }

    private List<Certificate> findCertificateChildren(String serial) {
        List<Certificate> certificates = this.certificateRepository.findAllByIssuerSerial(serial);
        List<Certificate> children = new ArrayList<>();
        for (Certificate c : certificates) {
            if (serial.equals(c.getSerialNumber())) continue;
            children.add(c);
            children.addAll(findCertificateChildren(c.getSerialNumber()));
        }
        return children;
    }


    public Certificate createRoot(CertificateRequestDto dto) {
        //Generate applicative certificate
        BigInteger uuid = generateUniqueBigInteger();
        Certificate cert = dto.mapToModel();
        cert.setRevocationStatus(false);
        cert.setKeystore("root.jks");
        cert.setSerialNumber(uuid.toString());
        cert.setIssuerSerial(uuid.toString());
        KeyPair keyPair = generateKeyPair();
        int usage = getUsage(dto.getExtensions(),null);
        usage = usage | KeyUsage.digitalSignature | KeyUsage.keyCertSign;
        //TODO: validate data from issuer and for current certificate
        //Generate bouncy castle certificate with cert data
        if (!verifyDateRange(dto.getStartDate(), dto.getEndDate(), cert)) {
            throw new CertificateDateNotValidException();
        }
        X509Certificate certificate = null;
        try {
            certificate = generateCertificate(cert.toSubject(keyPair.getPublic()),
                    cert.toIssuer(keyPair.getPrivate(), keyPair.getPublic()), cert.getValidFrom(), cert.getValidTo(), cert.getSerialNumber(), usage, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        //Load everything to store
        Keystore keystore = keystoreService.findOrCreate("root.jks");
        String password = encryptionService.decrypt(keystore.getPassword());
        fileKeystoreService.load("root.jks");
        fileKeystoreService.write(certificate.getSerialNumber().toString(), keyPair.getPrivate(), password.toCharArray(), certificate);
        fileKeystoreService.save("root.jks");

        cert = certificateRepository.save(cert);
        return cert;
    }

    private static int getUsage(KeyUsageDto extensions, boolean[] issuerKeyUsage) {
        int usage = 0;
        
        if(extensions.getCRLSign()){
            if(issuerKeyUsage != null) {
                boolean isIssuerCRLSignEnabled = issuerKeyUsage[6];
                if (!isIssuerCRLSignEnabled) throw new CreateCertificateExtensionsException();
            }
            usage = usage | KeyUsage.cRLSign;
        }
        
        if(extensions.getKeyEncipherment()){
            if(issuerKeyUsage != null) {
                boolean isIssuerKeyEnciphermentEnabled = issuerKeyUsage[2];
                if (!isIssuerKeyEnciphermentEnabled) throw new CreateCertificateExtensionsException();
            }
            usage = usage | KeyUsage.keyEncipherment;
        }
        
        if(extensions.getNonRepudiation()){
            if(issuerKeyUsage != null) {
                boolean isIssuerNonRepudiationEnabled = issuerKeyUsage[1];
                if (!isIssuerNonRepudiationEnabled) throw new CreateCertificateExtensionsException();
            }
            usage = usage | KeyUsage.nonRepudiation;
        }
        
        if(extensions.getDataEncipherment()){
            if(issuerKeyUsage != null){
                boolean isIssuerDataEnciphermentEnabled = issuerKeyUsage[3];
                if(!isIssuerDataEnciphermentEnabled) throw new CreateCertificateExtensionsException();
            }
            usage = usage | KeyUsage.dataEncipherment;
        }
        
        return usage;
    }

    public Certificate createIntermediary(CertificateRequestDto dto) {
        BigInteger uuid = generateUniqueBigInteger();
        Certificate issuerCert = certificateRepository.findOneBySerialNumber(dto.getIssuerId());
        if (issuerCert == null) {
            throw new RuntimeException("Issuer doesn't exist!");
        }
        Keystore issuerKeystore = this.keystoreService.findByName(issuerCert.getKeystore());
        String decodedPassword = encryptionService.decrypt(issuerKeystore.getPassword());
        PrivateKey issuerPrivateKey = fileKeystoreService.readPrivateKeyFromIssuer(issuerCert.getKeystore(),decodedPassword,issuerCert.getSerialNumber());
        X509Certificate issuerCertificate = (X509Certificate) fileKeystoreService.readCertificate(issuerCert.getKeystore(),decodedPassword,issuerCert.getSerialNumber());
        Certificate cert = dto.mapToModel();
        cert.setRevocationStatus(false);
        cert.setKeystore("intermediary.jks");
        cert.setSerialNumber(uuid.toString());
        KeyPair keyPair = generateKeyPair();
        
        boolean isIssuerCA = issuerCertificate.getBasicConstraints() > 0;
        if(!isIssuerCA) throw new NoPermissionToGenerateCertificateException();
        if (!verifyUsage(issuerCert)) {
            throw new NoPermissionToGenerateCertificateException();
        }
        boolean[] issuerKeyUsage = issuerCertificate.getKeyUsage();
        int usage = getUsage(dto.getExtensions(),issuerKeyUsage);
        usage = usage | KeyUsage.digitalSignature | KeyUsage.keyCertSign;
        //TODO: validate data from issuer and for current certificate
        if (!verifyDateRange(dto.getStartDate(), dto.getEndDate(), issuerCert)) {
            throw new CertificateDateNotValidException();
        }
        if (issuerCert.isRevocationStatus()) {
            throw new IssuerRevokedException();
        }
        X509Certificate certificate = null;
        try {
            certificate = generateCertificate(cert.toSubject(keyPair.getPublic()),
                    issuerCert.toIssuer(issuerPrivateKey,issuerCertificate.getPublicKey()), cert.getValidFrom(), cert.getValidTo(), cert.getSerialNumber(), usage, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Keystore keystore = keystoreService.findOrCreate("intermediary.jks");
        String password = encryptionService.decrypt(keystore.getPassword());
        fileKeystoreService.load("intermediary.jks");
        fileKeystoreService.write(certificate.getSerialNumber().toString(), keyPair.getPrivate(), password.toCharArray(), certificate);
        fileKeystoreService.save("intermediary.jks");
        cert = certificateRepository.save(cert);
        return cert;
    }

    public Certificate createEndCertificate(CertificateRequestDto dto) {
        BigInteger uuid = generateUniqueBigInteger();
        Certificate issuerCert = certificateRepository.findOneBySerialNumber(dto.getIssuerId());
        if (issuerCert == null) {
            throw new RuntimeException("Issuer doesn't exist!");
        }
        Keystore issuerKeystore = this.keystoreService.findByName(issuerCert.getKeystore());
        String decodedPassword = encryptionService.decrypt(issuerKeystore.getPassword());
        PrivateKey issuerPrivateKey = fileKeystoreService.readPrivateKeyFromIssuer(issuerCert.getKeystore(),decodedPassword,issuerCert.getSerialNumber());
        X509Certificate issuerCertificate = (X509Certificate) fileKeystoreService.readCertificate(issuerCert.getKeystore(),decodedPassword,issuerCert.getSerialNumber());
        Certificate cert = dto.mapToModel();
        cert.setRevocationStatus(false);
        cert.setKeystore("endCertificate.jks");
        cert.setSerialNumber(uuid.toString());
        KeyPair keyPair = generateKeyPair();

        boolean isIssuerCA = issuerCertificate.getBasicConstraints() == 1;
        if(!isIssuerCA) throw new NoPermissionToGenerateCertificateException();
        if (!verifyUsage(issuerCert)) {
            throw new NoPermissionToGenerateCertificateException();
        }

        boolean[] issuerKeyUsage = issuerCertificate.getKeyUsage();
        int usage = getUsage(dto.getExtensions(),issuerKeyUsage);
        usage = usage | KeyUsage.digitalSignature;
        
        //TODO: validate data from issuer and for current certificate
        if (!verifyDateRange(dto.getStartDate(), dto.getEndDate(), issuerCert)) {
            throw new CertificateDateNotValidException();
        }
        if (issuerCert.isRevocationStatus()) {
            throw new IssuerRevokedException();
        }
        X509Certificate certificate = null;
        try {
            certificate = generateCertificate(cert.toSubject(keyPair.getPublic()),
                    issuerCert.toIssuer(issuerPrivateKey, issuerCertificate.getPublicKey()), cert.getValidFrom(), cert.getValidTo(), cert.getSerialNumber(), usage, false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        Keystore keystore = keystoreService.findOrCreate("endCertificate.jks");
        String password = encryptionService.decrypt(keystore.getPassword());
        fileKeystoreService.load("endCertificate.jks");
        fileKeystoreService.write(certificate.getSerialNumber().toString(), keyPair.getPrivate(), password.toCharArray(), certificate);
        fileKeystoreService.save("endCertificate.jks");
        cert = certificateRepository.save(cert);
        return cert;
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void verifyCertificate(X509Certificate certificate) {
        Certificate subjectCertificate = certificateRepository.findOneBySerialNumber(String.valueOf(certificate.getSerialNumber()));
        if (subjectCertificate == null) throw new CertificateNotFoundException();
        if (subjectCertificate.isRevocationStatus()) throw new IssuerRevokedException();
        Certificate issuerCertificate = certificateRepository.findOneBySerialNumber(subjectCertificate.getIssuerSerial());
        if (issuerCertificate == null) throw new CertificateNotFoundException();
        Keystore issuerKeyStore = this.keystoreService.findByName(issuerCertificate.getKeystore());
        String issuerKeystoreDecodedPassword = encryptionService.decrypt(issuerKeyStore.getPassword());
        PublicKey issuerPublicKey = fileKeystoreService.readCertificate(issuerCertificate.getKeystore(), issuerKeystoreDecodedPassword, issuerCertificate.getSerialNumber().toString()).getPublicKey();
        try {
            certificate.verify(issuerPublicKey);
        } catch (CertificateException e) {
            throw new VerificationFailedException();
        } catch (NoSuchAlgorithmException e) {
            throw new VerificationFailedException();
        } catch (InvalidKeyException e) {
            throw new VerificationFailedException();
        } catch (NoSuchProviderException e) {
            throw new VerificationFailedException();
        } catch (SignatureException e) {
            throw new VerificationFailedException();
        }
    }

    public void handleRevokeCertificate(String serialNumber) {
        revokeCertificate(serialNumber);
        revokeChildren(serialNumber);
    }

    public RevocationDto checkIfCertificateRevoked(String serialNumber) {
        Certificate certificate = certificateRepository.findOneBySerialNumber(serialNumber);
        if (certificate.isRevocationStatus()) return new RevocationDto(true, certificate.getRevocationDate());
        if (certificate.getValidTo().before(new Date())) {
            revokeCertificate(serialNumber);
            return new RevocationDto(true, certificate.getRevocationDate());
        }
        return new RevocationDto(false, null);
    }

    private void revokeChildren(String serialNumber) {
        List<Certificate> certificates = certificateRepository.findAllByIssuerSerial(serialNumber);
        for (Certificate c : certificates) {
            if (c.getSerialNumber().equals(serialNumber)) continue;
            revokeCertificate(c.getSerialNumber());
            revokeChildren(c.getSerialNumber());
        }
    }

    private void revokeCertificate(String serialNumber) {
        Certificate certificate = certificateRepository.findOneBySerialNumber(serialNumber);
        certificate.setRevocationStatus(true);
        certificate.setRevocationDate(new Date());
        certificateRepository.save(certificate);
    }

    private BigInteger generateUniqueBigInteger() {
        SecureRandom random = new SecureRandom();
        BigInteger bigInt;
        do {
            bigInt = new BigInteger(20, random);
        } while (bigInt.equals(BigInteger.ZERO));

        return bigInt;
    }

    private boolean verifyDateRange(Date from, Date to, Certificate issuerCertificate) {
        boolean isIssuerDateAfterSubjectStart = issuerCertificate.getValidFrom().after(from);
        boolean isIssuerDateBeforeSubjectEnd = issuerCertificate.getValidTo().before(to);
        return !isIssuerDateAfterSubjectStart && !isIssuerDateBeforeSubjectEnd;
    }

    private boolean verifyUsage(Certificate issuerCertificate) {
        Keystore keystore = keystoreService.findByName(issuerCertificate.getKeystore());
        String password = encryptionService.decrypt(keystore.getPassword());
        X509Certificate cert = (X509Certificate) fileKeystoreService.readCertificate(keystore.getName(), password, issuerCertificate.getSerialNumber());
        boolean[] tmp = cert.getKeyUsage();

        return tmp[5];
    }

    public byte[] downloadCertificate(String id) throws CertificateEncodingException {
        Certificate certificate = certificateRepository.findOneBySerialNumber(id);
        Keystore keystore = keystoreService.findByName(certificate.getKeystore());
        String password = encryptionService.decrypt(keystore.getPassword());
        X509Certificate cert = (X509Certificate) fileKeystoreService.readCertificate(keystore.getName(), password, certificate.getSerialNumber());
        return cert.getEncoded();
    }

    public PageDto<Certificate> findAll(int pageNumber, int pageSize) {
        Page<Certificate> page = certificateRepository.findAll(PageRequest.of(pageNumber, pageSize));
        return new PageDto<>(page.getContent(), page.getTotalPages());
    }

    public List<Certificate> findIssuers() {
        return this.certificateRepository.findAllCAs();
    }
}

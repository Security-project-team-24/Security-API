package team24.security.service;

import lombok.AllArgsConstructor;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import team24.security.dto.CertificateRequestDto;
import team24.security.dto.RevocationDto;
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
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.bouncycastle.asn1.x500.style.RFC4519Style.serialNumber;

@Service
@AllArgsConstructor
public class CertificateService {

    private ICertificateRepository certificateRepository;
    private FileKeystoreService fileKeystoreService;
    private KeystoreService keystoreService;
    private EncryptionService encryptionService;

    private X509Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber, int usage) {
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

            certGen.addExtension(Extension.keyUsage, false, new KeyUsage(usage));
            
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

    public Certificate createRoot(CertificateRequestDto dto) {
        //Generate applicative certificate
        BigInteger uuid = generateUniqueBigInteger();
        Certificate cert = dto.mapToModel();
        cert.setRevocationStatus(false);
        cert.setKeystore("root.jks");
        cert.setSerialNumber(uuid.toString());
        cert.setIssuerSerial(uuid.toString());
        int usage = KeyUsage.cRLSign | KeyUsage.keyCertSign | KeyUsage.digitalSignature;;
        //TODO: validate data from issuer and for current certificate
        //Generate bouncy castle certificate with cert data
        if (!verifyDateRange(dto.startDate, dto.endDate, cert)){
            throw new RuntimeException("Date is not valid");
        }
        X509Certificate certificate = generateCertificate(cert.toSubject(),
                cert.toIssuer(), cert.getValidFrom(), cert.getValidTo(), cert.getSerialNumber(), usage);

        //Load everything to store
        Keystore keystore = keystoreService.findOrCreate("root.jks");
        String password = encryptionService.decrypt(keystore.getPassword());
        fileKeystoreService.load("root.jks");
        fileKeystoreService.write(certificate.getSerialNumber().toString(), cert.toIssuer().getPrivateKey(), password.toCharArray(), certificate);
        fileKeystoreService.save("root.jks");

        cert = certificateRepository.save(cert);
        return cert;
    }

    public Certificate createIntermediary(CertificateRequestDto dto) {
        BigInteger uuid = generateUniqueBigInteger();
        Certificate issuerCert = certificateRepository.findOneBySerialNumber(dto.issuerId);
        if (issuerCert == null) {
            throw new RuntimeException("Issuer doesn't exist!");
        }
        Certificate cert = dto.mapToModel();
        cert.setRevocationStatus(false);
        cert.setKeystore("intermediary.jks");
        cert.setSerialNumber(uuid.toString());
        int usage = KeyUsage.cRLSign | KeyUsage.keyCertSign | KeyUsage.digitalSignature;
        //TODO: validate data from issuer and for current certificate
        if (!verifyDateRange(dto.startDate, dto.endDate, issuerCert)){
            throw new RuntimeException("Date is not valid");
        }
        if (!verifyUsage(issuerCert)){
            throw new RuntimeException("Issuer cannot generate");
        }
        if (issuerCert.isRevocationStatus()){
            throw new RuntimeException("Issuer is revoked");
        }
        X509Certificate certificate = generateCertificate(cert.toSubject(),
                issuerCert.toIssuer(), cert.getValidFrom(), cert.getValidTo(), cert.getSerialNumber(), usage);

        Keystore keystore = keystoreService.findOrCreate("intermediary.jks");
        String password = encryptionService.decrypt(keystore.getPassword());
        fileKeystoreService.load("intermediary.jks");
        fileKeystoreService.write(certificate.getSerialNumber().toString(), cert.toIssuer().getPrivateKey(), password.toCharArray(), certificate);
        fileKeystoreService.save("intermediary.jks");
        cert = certificateRepository.save(cert);
        return cert;
    }

    public Certificate createEndCertificate(CertificateRequestDto dto) {
        BigInteger uuid = generateUniqueBigInteger();
        Certificate issuerCert = certificateRepository.findOneBySerialNumber(dto.issuerId);
        if (issuerCert == null) {
            throw new RuntimeException("Issuer doesn't exist!");
        }
        Certificate cert = dto.mapToModel();
        cert.setRevocationStatus(false);
        cert.setKeystore("endCertificate.jks");
        cert.setSerialNumber(uuid.toString());
        int usage =  KeyUsage.digitalSignature;
        //TODO: validate data from issuer and for current certificate
        if (!verifyDateRange(dto.startDate, dto.endDate, issuerCert)){
            throw new RuntimeException("Date is not valid");
        }
        if (!verifyUsage(issuerCert)){
            throw new RuntimeException("Issuer cannot generate");
        }
        if (issuerCert.isRevocationStatus()){
            throw new RuntimeException("Issuer is revoked");
        }
        X509Certificate certificate = generateCertificate(cert.toSubject(),
                issuerCert.toIssuer(), cert.getValidFrom(), cert.getValidTo(), cert.getSerialNumber(), usage);

        Keystore keystore = keystoreService.findOrCreate("endCertificate.jks");
        String password = encryptionService.decrypt(keystore.getPassword());
        fileKeystoreService.load("endCertificate.jks");
        fileKeystoreService.write(certificate.getSerialNumber().toString(), cert.toIssuer().getPrivateKey(), password.toCharArray(), certificate);
        fileKeystoreService.save("endCertificate.jks");
        cert = certificateRepository.save(cert);
        return cert;
    }

    public void handleRevokeCertificate(String serialNumber){
        revokeCertificate(serialNumber);
        revokeChildren(serialNumber);
    }

    public RevocationDto checkIfCertificateRevoked(String serialNumber){
        Certificate certificate = certificateRepository.findOneBySerialNumber(serialNumber);
        if(certificate.isRevocationStatus()) return new RevocationDto(true, certificate.getRevocationDate());
        if(certificate.getValidTo().before(new Date())){
            revokeCertificate(serialNumber);
            return new RevocationDto(true, certificate.getRevocationDate());
        }
        return new RevocationDto(false, null);
    }

    private void revokeChildren(String serialNumber){
        List<Certificate> certificates = certificateRepository.findAllByIssuerSerial(serialNumber);
        for(Certificate c : certificates){
            if(c.getSerialNumber().equals(serialNumber)) continue;
            revokeCertificate(c.getSerialNumber());
            revokeChildren(c.getSerialNumber());
        }
    }

    private void revokeCertificate(String serialNumber){
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

    private boolean verifyDateRange(Date from, Date to, Certificate issuerCertificate){
        boolean isIssuerDateAfterSubjectStart = issuerCertificate.getValidFrom().after(from);
        boolean isIssuerDateBeforeSubjectEnd = issuerCertificate.getValidTo().before(to);
        return !isIssuerDateAfterSubjectStart && !isIssuerDateBeforeSubjectEnd;
    }

    private boolean verifyUsage(Certificate issuerCertificate){
        Keystore keystore = keystoreService.findByName(issuerCertificate.getKeystore());
        String password = encryptionService.decrypt(keystore.getPassword());
        X509Certificate cert = (X509Certificate)fileKeystoreService.readCertificate(keystore.getName(), password, issuerCertificate.getSerialNumber());
        boolean[] tmp = cert.getKeyUsage();

        return tmp[5];
    }
    
}

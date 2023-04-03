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
import team24.security.model.Certificate;
import team24.security.model.Issuer;
import team24.security.model.Keystore;
import team24.security.model.Subject;
import team24.security.repository.ICertificateRepository;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;

import static org.bouncycastle.asn1.x500.style.RFC4519Style.serialNumber;

@Service
@AllArgsConstructor
public class CertificateService {

    private ICertificateRepository certificateRepository;
    private FileKeystoreService fileKeystoreService;
    private KeystoreService keystoreService;



    private Certificate create(Certificate certificate) {
        return certificateRepository.save(certificate);
    }

    public Certificate findById(UUID uuid) {
        return certificateRepository
                .findById(uuid)
                .orElseThrow(() -> new RuntimeException("Certificate doesn't exist!"));
    }

    public Certificate createRoot(CertificateRequestDto dto) {
        BigInteger uuid = generateUniqueBigInteger()
        Certificate cert = dto.mapToModel();
        cert.setSerialNumber(uuid.toString());
        cert.setIssuerSerial(uuid.toString());
        // Find or create keystore in database
        Keystore keystore = keystoreService.findOrCreate("root");
        // Find or create keystore in filesystem
        fileKeystoreService.loadKeyStore(keystore.getName());
        // Generate certificate for file system



        // Save certificate to database
        //Return generated certificate
        return cert;
    }


    private BigInteger generateUniqueBigInteger() {
        SecureRandom random = new SecureRandom();
        BigInteger bigInt;
        do {
            bigInt = new BigInteger(20, random);
        } while (bigInt.equals(BigInteger.ZERO));

        return bigInt;
    }

    public static X509Certificate generateCertificate(Subject subject, Issuer issuer, Date startDate, Date endDate, String serialNumber, int usage) {
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

        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }


}

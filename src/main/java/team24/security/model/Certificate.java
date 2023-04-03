package team24.security.model;


import jakarta.persistence.*;
import lombok.*;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.security.*;
import java.util.Date;
import java.util.UUID;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity(name = "certificate")
public class Certificate {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(name = "common_name")
    private String commonName;
    @Column(name = "surname")
    private String surname;
    @Column(name = "organization")
    private String organization;
    @Column(name = "email")
    private String email;
    @Column(name = "organization_unit")
    private String organizationUnit;
    @Column(name = "country")
    private String country;
    @Column(name = "serial_number", unique = true, nullable = false)
    private String serialNumber;
    @Column(name = "issuer_serial", nullable = false)
    private String issuerSerial;
    @Column(name = "valid_from")
    private Date validFrom;
    @Column(name = "valid_to")
    private Date validTo;
    @Column(name = "keystore")
    private String keystore;
    @Column(name = "revocation_status")
    private boolean revocationStatus;

    public Subject toSubject() {
        KeyPair keyPairSubject = generateKeyPair();
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, this.commonName);
        builder.addRDN(BCStyle.SURNAME, this.surname);
        builder.addRDN(BCStyle.GIVENNAME, this.commonName);
        builder.addRDN(BCStyle.O, this.organization);
        builder.addRDN(BCStyle.OU, this.organizationUnit);
        builder.addRDN(BCStyle.C, this.country);
        builder.addRDN(BCStyle.E, this.email);
        builder.addRDN(BCStyle.UID, this.serialNumber);
        return new Subject(keyPairSubject.getPublic(), builder.build());
    }

    public Issuer toIssuer() {
        KeyPair kp = generateKeyPair();
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, this.commonName);
        builder.addRDN(BCStyle.SURNAME, this.surname);
        builder.addRDN(BCStyle.GIVENNAME, this.commonName);
        builder.addRDN(BCStyle.O, this.organization);
        builder.addRDN(BCStyle.OU, this.organizationUnit);
        builder.addRDN(BCStyle.C, this.country);
        builder.addRDN(BCStyle.E, this.email);
        builder.addRDN(BCStyle.UID, this.serialNumber);
        return new Issuer(kp.getPrivate(), kp.getPublic(), builder.build());
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
}

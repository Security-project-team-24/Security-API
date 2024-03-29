package team24.security.model;


import javax.persistence.*;
import lombok.*;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.hibernate.annotations.GenericGenerator;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
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
    @Column(name = "revocation_date")
    private Date revocationDate;

    public Subject toSubject(PublicKey publicKey) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, this.commonName);
        builder.addRDN(BCStyle.SURNAME, this.surname);
        builder.addRDN(BCStyle.GIVENNAME, this.commonName);
        builder.addRDN(BCStyle.O, this.organization);
        builder.addRDN(BCStyle.OU, this.organizationUnit);
        builder.addRDN(BCStyle.C, this.country);
        builder.addRDN(BCStyle.E, this.email);
        builder.addRDN(BCStyle.UID, this.serialNumber);
        return new Subject(publicKey, builder.build());
    }

    public Issuer toIssuer(PrivateKey privateKey,PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, this.commonName);
        builder.addRDN(BCStyle.SURNAME, this.surname);
        builder.addRDN(BCStyle.GIVENNAME, this.commonName);
        builder.addRDN(BCStyle.O, this.organization);
        builder.addRDN(BCStyle.OU, this.organizationUnit);
        builder.addRDN(BCStyle.C, this.country);
        builder.addRDN(BCStyle.E, this.email);
        builder.addRDN(BCStyle.UID, this.serialNumber);
        return new Issuer(privateKey, publicKey, builder.build());
    }
}

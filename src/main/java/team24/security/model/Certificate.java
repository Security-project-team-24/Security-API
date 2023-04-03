package team24.security.model;


import jakarta.persistence.*;
import lombok.*;

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
    private String county;
    @Column(name = "uuid", unique = true, nullable = false)
    private String serialNumber;
    @Column(name = "issuer", nullable = false)
    private String issuerSerial;
    @Column(name = "valid_from")
    private Date validFrom;
    @Column(name = "valid_to")
    private Date validTo;
}

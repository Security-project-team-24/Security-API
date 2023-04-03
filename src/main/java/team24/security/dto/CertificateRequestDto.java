package team24.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import team24.security.model.Certificate;

import java.util.Date;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CertificateRequestDto {
    public SubjectDto subject;
    public String issuerId;
    public Date startDate;
    public Date endDate;


    public Certificate mapToModel() {
        return Certificate
                .builder()
                .commonName(subject.commonName)
                .surname(subject.surname)
                .organization(subject.organization)
                .organizationUnit(subject.organizationUnit)
                .email(subject.email)
                .county(subject.country)
                .issuer(UUID.fromString(issuerId))
                .validFrom(startDate)
                .validTo(endDate)
                .build();
    }
}

package team24.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import team24.security.model.Certificate;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CertificateRequestDto {
    SubjectDto subject;
    String issuerId;
    Date startDate;
    Date endDate;
    KeyUsageDto extensions;


    public Certificate mapToModel() {
        return Certificate
                .builder()
                .commonName(subject.commonName)
                .surname(subject.surname)
                .organization(subject.organization)
                .organizationUnit(subject.organizationUnit)
                .email(subject.email)
                .country(subject.country)
                .issuerSerial(issuerId)
                .validFrom(startDate)
                .validTo(endDate)
                .build();
    }
}

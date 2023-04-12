package team24.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SubjectDto {
    String commonName;
    String surname;
    String givenName;
    String organization;
    String organizationUnit;
    String country;
    String email;
}

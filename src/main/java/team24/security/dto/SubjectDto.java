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
    public String commonName;
    public String surname;
    public String givenName;
    public String organization;
    public String organizationUnit;
    public String country;
    public String email;
}

package team24.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class KeyUsageDto {
    
    Boolean cRLSign;
    Boolean keyEncipherment;
    Boolean nonRepudiation;
    Boolean dataEncipherment;
}

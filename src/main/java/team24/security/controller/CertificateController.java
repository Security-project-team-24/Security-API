package team24.security.controller;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import team24.security.service.CertificateService;

@RestController
@RequestMapping(value = "/api/certificate")
@AllArgsConstructor
public class CertificateController {
    
    private CertificateService certificateService;
}

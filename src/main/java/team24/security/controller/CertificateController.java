package team24.security.controller;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import team24.security.dto.CertificateRequestDto;
import team24.security.model.Certificate;
import team24.security.service.CertificateService;

@RestController
@RequestMapping(value = "/api/certificate")
@AllArgsConstructor
public class CertificateController {
    private CertificateService certificateService;

    @PostMapping("/root")
    public ResponseEntity<Certificate> createRoot(
            @RequestBody CertificateRequestDto dto
    ) {
        Certificate cert = certificateService.createRoot(dto);
        return new ResponseEntity<>(cert, HttpStatus.OK);
    }


    @PostMapping("/intermediary")
    public ResponseEntity<Certificate> createIntermediary(
            @RequestBody CertificateRequestDto dto
    ) {
        Certificate cert = certificateService.createIntermediary(dto);
        return new ResponseEntity<>(cert, HttpStatus.OK);
    }
}

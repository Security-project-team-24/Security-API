package team24.security.controller;

import lombok.AllArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import team24.security.dto.CertificateRequestDto;
import team24.security.dto.PageDto;
import team24.security.dto.RevocationDto;
import team24.security.model.Certificate;
import team24.security.service.CertificateService;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

@CrossOrigin(origins = "http://localhost:3000")
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
    @PostMapping("/end")
    public ResponseEntity<Certificate> createEndCertificate(
            @RequestBody CertificateRequestDto dto
    ) {
        Certificate cert = certificateService.createEndCertificate(dto);
        return new ResponseEntity<>(cert, HttpStatus.OK);
    }

    @PatchMapping("/{id}/revoke")
    public ResponseEntity revokeCertificate(@PathVariable String id){
        certificateService.handleRevokeCertificate(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @GetMapping("/{id}/revoke/check")
    public ResponseEntity<RevocationDto> checkIfCertificateRevoked(@PathVariable String id){
        RevocationDto revocation = certificateService.checkIfCertificateRevoked(id);
        return new ResponseEntity<>(revocation, HttpStatus.OK);
    }

    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> download(@PathVariable String id){
        byte[] certificateBytes = new byte[0];
        try {
            certificateBytes = certificateService.downloadCertificate(id);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(certificateBytes);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", "certificate.crt");

        return ResponseEntity.ok()
                .headers(headers)
                .body(certificateBytes);
    }
    @PostMapping(value = "/verify")
    public ResponseEntity<Boolean> uploadFile(@RequestParam("file") MultipartFile file) {
        InputStream inputStream = null;
        try {
            inputStream = file.getInputStream();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            System.out.println(certificate.getSerialNumber());
            Boolean isCertificateValid = certificateService.verifyCertificate(certificate);
        } catch (Exception e) {
            return new ResponseEntity<>(false, HttpStatus.OK);
        }
        return new ResponseEntity<>(true, HttpStatus.OK);
    }

    @GetMapping("/findAll/{pageNumber}/{pageSize}")
    public ResponseEntity<PageDto<Certificate>> findAll(@PathVariable int pageNumber, @PathVariable int pageSize){
        PageDto<Certificate> certificates = certificateService.findAll(pageNumber, pageSize);
        return new ResponseEntity<>(certificates, HttpStatus.OK);
    }

    @GetMapping("/issuer")
    public ResponseEntity<List<Certificate>> findIssuers(){
        List<Certificate> certificates = certificateService.findIssuers();
        return new ResponseEntity<>(certificates, HttpStatus.OK);
    }
}

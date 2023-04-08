package team24.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.io.IOException;
import java.security.Security;

@SpringBootApplication
@EnableSwagger2
public class SecurityApplication {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        SpringApplication.run(SecurityApplication.class, args);
        openSwagger();
    }

    private static void openSwagger() {
        Runtime rt = Runtime.getRuntime();
        try {
            rt.exec("rundll32 url.dll,FileProtocolHandler " + "http://localhost:8000/swagger-ui.html");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

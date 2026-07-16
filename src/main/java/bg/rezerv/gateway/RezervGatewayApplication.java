package bg.rezerv.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class RezervGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(RezervGatewayApplication.class, args);
    }
}

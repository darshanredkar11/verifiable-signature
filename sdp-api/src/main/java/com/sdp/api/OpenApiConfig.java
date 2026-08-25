package com.sdp.api;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI sdpOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("SDP-1: Semantic Delta Proof Engine API")
                        .description("A cryptographic REST API for producing and verifying semantic delta evidence " +
                                "between document representations (PDF/A, OCR, locale reformatting) using Merkle tree " +
                                "commitments and Ed25519 signatures.")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("SDP-1 Protocol Team")
                                .email("contact@sdp-engine.org"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("Local Development Server")
                ));
    }
}

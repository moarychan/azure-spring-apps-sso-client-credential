package com.books.gateway.config;

import com.azure.spring.cloud.autoconfigure.aad.configuration.AadPropertiesConfiguration;
import com.azure.spring.cloud.autoconfigure.aad.implementation.constants.AadJwtClaimNames;
import com.azure.spring.cloud.autoconfigure.aad.implementation.jwt.AadJwtGrantedAuthoritiesConverter;
import com.azure.spring.cloud.autoconfigure.aad.implementation.webapi.validator.AadJwtIssuerValidator;
import com.azure.spring.cloud.autoconfigure.aad.properties.AadAuthenticationProperties;
import com.azure.spring.cloud.autoconfigure.aad.properties.AadResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@Import(AadPropertiesConfiguration.class)
public class SecurityConfiguration {

    private AadAuthenticationProperties aadAuthenticationProperties;
    private AadResourceServerProperties aadResourceServerProperties;

    public SecurityConfiguration(AadAuthenticationProperties aadAuthenticationProperties, AadResourceServerProperties aadResourceServerProperties) {
        this.aadAuthenticationProperties = aadAuthenticationProperties;
        this.aadResourceServerProperties = aadResourceServerProperties;
    }

    @Bean
    public SecurityWebFilterChain defaultAadResourceServerFilterChain(ServerHttpSecurity http) throws Exception {
        // @formatter:off
        http
            .csrf()
                .disable()
            .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter()).jwtDecoder(jwtDecoder());
        // @formatter:off
        return http.build();
    }

    public ReactiveJwtDecoder jwtDecoder() {
        NimbusReactiveJwtDecoder jwtDecoder = (NimbusReactiveJwtDecoder)
            ReactiveJwtDecoders.fromIssuerLocation("https://login.microsoftonline.com/" + aadAuthenticationProperties.getProfile().getTenantId() + "/v2.0");
        jwtDecoder.setJwtValidator(createOAuth2TokenValidator());
        return jwtDecoder;
    }

    public OAuth2TokenValidator<Jwt> createOAuth2TokenValidator() {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        List<String> validAudiences = new ArrayList<>();
        if (StringUtils.hasText(aadAuthenticationProperties.getAppIdUri())) {
            validAudiences.add(aadAuthenticationProperties.getAppIdUri());
        }
        if (StringUtils.hasText(aadAuthenticationProperties.getCredential().getClientId())) {
            validAudiences.add(aadAuthenticationProperties.getCredential().getClientId());
        }
        if (!validAudiences.isEmpty()) {
            validators.add(new JwtClaimValidator<List<String>>(AadJwtClaimNames.AUD, validAudiences::containsAll));
        }
        validators.add(new AadJwtIssuerValidator());
        validators.add(new JwtTimestampValidator());

        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        if (StringUtils.hasText(aadResourceServerProperties.getPrincipalClaimName())) {
            converter.setPrincipalClaimName(aadResourceServerProperties.getPrincipalClaimName());
        }

        converter.setJwtGrantedAuthoritiesConverter(
            new AadJwtGrantedAuthoritiesConverter(aadResourceServerProperties.getClaimToAuthorityPrefixMap()));
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }
}

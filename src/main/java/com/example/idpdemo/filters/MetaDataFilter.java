package com.example.idpdemo.filters;

import com.example.idpdemo.config.IdpConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;

/*@Component
@Order(1)*/
public class MetaDataFilter extends OncePerRequestFilter {
    private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/**/metadata", HttpMethod.GET.name());
    private final IdpConfig idpConfig;
    private final HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();;
    public MetaDataFilter(IdpConfig idpConfig) {
        this.idpConfig = idpConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (requestMatcher.matches(request)) {
            IdentityProviderService provider = idpConfig.getSamlProvisioning().getHostedProvider();
            String xml = provider.toXml(provider.getMetadata());
            cacheHeaderWriter.writeHeaders(request, response);
            response.setContentType(TEXT_XML_VALUE);
            String safeFilename = URLEncoder.encode("metadata.xml", "ISO-8859-1");
            response.addHeader(CONTENT_DISPOSITION, "attachment; filename=\"" + safeFilename + "\"" + ";");
            response.getWriter().write(xml);
        } else {
            filterChain.doFilter(request, response);
        }
    }
}

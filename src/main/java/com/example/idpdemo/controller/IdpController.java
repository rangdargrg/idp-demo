package com.example.idpdemo.controller;

import com.example.idpdemo.config.IdpConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URLEncoder;

import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;
import static org.springframework.util.StringUtils.getFilename;

@Controller
public class IdpController {
    @Autowired
    private IdpConfig idpConfig;

    private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

   /* @GetMapping("/metadata")
    public void metadata(HttpServletRequest request, HttpServletResponse response) throws IOException {
        IdentityProviderService provider = idpConfig.getSamlProvisioning().getHostedProvider();
        String xml = provider.toXml(provider.getMetadata());
        cacheHeaderWriter.writeHeaders(request, response);
        response.setContentType(TEXT_XML_VALUE);
        String safeFilename = URLEncoder.encode("metadata.xml", "ISO-8859-1");
        response.addHeader(CONTENT_DISPOSITION, "attachment; filename=\"" + safeFilename + "\"" + ";");
        response.getWriter().write(xml);
    }*/
}

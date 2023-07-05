package com.example.idpdemo.controller;

import com.example.idpdemo.config.IdpConfig;
import com.example.idpdemo.domain.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;
import static org.springframework.util.StringUtils.getFilename;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class IdpController {
    @Autowired
    private IdpConfig idpConfig;

    private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();
    private SamlTemplateEngine samlTemplateEngine = new OpenSamlVelocityEngine();
    private final String postBindingTemplate = "/templates/saml2-post-binding.vm";


   @GetMapping("/saml/idp/metadata")
    public void metadata(HttpServletRequest request, HttpServletResponse response) throws IOException {
        IdentityProviderService provider = idpConfig.getSamlProvisioning().getHostedProvider();
        String xml = provider.toXml(provider.getMetadata());
        cacheHeaderWriter.writeHeaders(request, response);
        response.setContentType(TEXT_XML_VALUE);
        String safeFilename = URLEncoder.encode("metadata.xml", "ISO-8859-1");
        response.addHeader(CONTENT_DISPOSITION, "atta chment; filename=\"" + safeFilename + "\"" + ";");
        response.getWriter().write(xml);
    }
    @GetMapping("/saml/idp/SSO/alias/my-identity-provider-app")
    public void auth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        User user = (User) request.getSession().getAttribute("user");
        if (Objects.nonNull(user)) {
            IdentityProviderService provider = idpConfig.getSamlProvisioning().getHostedProvider();
            ServiceProviderMetadata recipient = getTargetProvider(request);
            AuthenticationRequest authenticationRequest = null;
            Assertion assertion = getAssertion(user.getLoginId(), null, provider, recipient);
            idpConfig.samlAssertionStore().addMessage(request, assertion.getId(), assertion);
            Response r = provider.response(null , assertion, recipient);

            Endpoint acsUrl = provider.getPreferredEndpoint(
                    recipient.getServiceProvider().getAssertionConsumerService(),
                    Binding.POST,
                    -1
            );


            String relayState = request.getParameter("RelayState");
            if (acsUrl.getBinding() == Binding.REDIRECT) {
                String encoded = provider.toEncodedXml(r, true);
                UriComponentsBuilder url = UriComponentsBuilder.fromUriString(acsUrl.getLocation());
                url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
                if (hasText(relayState)) {
                    url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
                }
                String redirect = url.build(true).toUriString();
                response.sendRedirect(redirect);
            }
            else if (acsUrl.getBinding() == Binding.POST) {
                String encoded = provider.toEncodedXml(r, false);
                Map<String, Object> model = new HashMap<>();
                model.put("action", acsUrl.getLocation());
                model.put("SAMLResponse", encoded);
                if (hasText(relayState)) {
                    model.put("RelayState", HtmlUtils.htmlEscape(relayState));
                }
                processHtml(request, response, postBindingTemplate, model);
            }
            else {
                throw new SamlException("Unsupported binding:" + acsUrl.getBinding());
            }
        }
        else {
            HttpSessionRequestCache cache = new HttpSessionRequestCache();
            cache.saveRequest(request, response);
            response.sendRedirect("/this-is-idp/login");

        }
    }

    protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
        IdentityProviderService provider = idpConfig.getSamlProvisioning().getHostedProvider();
        String param = request.getParameter("SAMLRequest");
        AuthenticationRequest authn =
                provider.fromXml(
                        param,
                        true,
                        HttpMethod.GET.name().equalsIgnoreCase(request.getMethod()),
                        AuthenticationRequest.class
                );
        provider.validate(authn);
        return provider.getRemoteProvider(authn);
    }
    protected Assertion getAssertion(String loginId,
                                     AuthenticationRequest authenticationRequest,
                                     IdentityProviderService provider,
                                     ServiceProviderMetadata recipient) {
        Assertion assertion = provider.assertion(recipient, loginId, NameId.PERSISTENT);
        return assertion;
    }

    protected void processHtml(HttpServletRequest request,
                               HttpServletResponse response,
                               String html,
                               Map<String, Object> model) {
        cacheHeaderWriter.writeHeaders(request, response);
        response.setContentType(TEXT_HTML_VALUE);
        response.setCharacterEncoding(UTF_8.name());
        StringWriter out = new StringWriter();
        samlTemplateEngine.process(
                request,
                html,
                model,
                out
        );
        try {
            response.getWriter().write(out.toString());
        } catch (IOException e) {
            throw new SamlException(e);
        }
    }

}

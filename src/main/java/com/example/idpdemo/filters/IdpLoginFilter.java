package com.example.idpdemo.filters;

import com.example.idpdemo.config.IdpConfig;
import com.example.idpdemo.domain.User;
import org.springframework.core.annotation.Order;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.lang.String.format;
import static org.springframework.util.StringUtils.hasText;

/*@Component
@Order(2)*/
public class IdpLoginFilter extends SamlFilter {
    RequestMatcher requestMatcher = new AntPathRequestMatcher("/**/init", HttpMethod.GET.name());
    RequestMatcher loginRequestMatcher = new AntPathRequestMatcher("/**/login", HttpMethod.GET.name());
    final IdpConfig idpConfig;
    private final String postBindingTemplate = "/templates/saml2-post-binding.vm";
    public IdpLoginFilter(IdpConfig idpConfig) {
        super(idpConfig.getSamlProvisioning());
        this.idpConfig = idpConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        User user = (User) request.getSession().getAttribute("user");
        if (requestMatcher.matches(request) &&
                Objects.nonNull(user)) {
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
            filterChain.doFilter(request, response);
        }
    }

    protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
        String entityId = request.getParameter("sp");
        return idpConfig.getSamlProvisioning().getHostedProvider().getRemoteProvider(entityId);
    }

    protected Assertion getAssertion(String loginId,
                                     AuthenticationRequest authenticationRequest,
                                     IdentityProviderService provider,
                                     ServiceProviderMetadata recipient) {
        Assertion assertion = provider.assertion(recipient, loginId, NameId.PERSISTENT);
        return assertion;
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    protected String buildRedirectUrlToLoginPage(HttpServletRequest request, String loginForm) {
        PortResolver portResolver = new PortResolverImpl();
        int serverPort = portResolver.getServerPort(request);
        String scheme = request.getScheme();
        RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
        urlBuilder.setScheme(scheme);
        urlBuilder.setServerName(request.getServerName());
        urlBuilder.setPort(serverPort);
        urlBuilder.setContextPath(request.getContextPath());
        urlBuilder.setPathInfo(loginForm);
        return urlBuilder.getUrl();
    }
}

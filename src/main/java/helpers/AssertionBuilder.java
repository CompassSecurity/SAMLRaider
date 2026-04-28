package helpers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/// Builds a minimal but standards-compliant SAML 2.0 Assertion XML string.
/// Validity window: NotBefore = now−1h (absorbs clock skew),
///                 NotOnOrAfter = now+24h.
public class AssertionBuilder {

    public static String build(
            String issuer,
            String nameId,
            String nameIdFormat,
            String recipient,
            String audience) {

        String id  = "_" + UUID.randomUUID().toString().replace("-", "");
        String now = Instant.now().toString();
        String notBefore   = Instant.now().minus(1, ChronoUnit.HOURS).toString();
        String notOnOrAfter = Instant.now().plus(24, ChronoUnit.HOURS).toString();

        return """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="%s" IssueInstant="%s" Version="2.0">
                  <saml:Issuer>%s</saml:Issuer>
                  <saml:Subject>
                    <saml:NameID Format="%s">%s</saml:NameID>
                    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                      <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
                    </saml:SubjectConfirmation>
                  </saml:Subject>
                  <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
                    <saml:AudienceRestriction>
                      <saml:Audience>%s</saml:Audience>
                    </saml:AudienceRestriction>
                  </saml:Conditions>
                  <saml:AuthnStatement AuthnInstant="%s">
                    <saml:AuthnContext>
                      <saml:AuthnContextClassRef>
                        urn:oasis:names:tc:SAML:2.0:ac:classes:Password
                      </saml:AuthnContextClassRef>
                    </saml:AuthnContext>
                  </saml:AuthnStatement>
                </saml:Assertion>""".formatted(
                id, now,
                escapeXml(issuer),
                escapeXml(nameIdFormat),
                escapeXml(nameId),
                notOnOrAfter, escapeXml(recipient),
                notBefore, notOnOrAfter,
                escapeXml(audience),
                now);
    }

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&apos;");
    }

    private AssertionBuilder() {}
}

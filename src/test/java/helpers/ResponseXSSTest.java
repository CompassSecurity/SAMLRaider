package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ResponseXSSTest {

    private static final String SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1" Destination="https://sp.example.com/acs">
              <saml:Issuer>https://idp.example.com</saml:Issuer>
              <saml:Assertion ID="a1">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject>
                  <saml:NameID>user@example.com</saml:NameID>
                </saml:Subject>
                <saml:Conditions>
                  <saml:AudienceRestriction>
                    <saml:Audience>https://sp.example.com</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
              </saml:Assertion>
            </samlp:Response>
            """;

    @Test
    void destinationAttributeIsReplaced() throws Exception {
        String payload = "\"><script>alert(1)</script>";
        String out = ResponseXSS.apply(SAML, ResponseXSS.Target.DESTINATION, payload);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        Element response = (Element) doc.getElementsByTagNameNS("*", "Response").item(0);
        // DOM getAttribute returns the unescaped value — serializer handles escaping.
        assertEquals(payload, response.getAttribute("Destination"));
    }

    @Test
    void issuerTextContentIsReplaced() throws Exception {
        String payload = "<img src=x onerror=alert(1)>";
        String out = ResponseXSS.apply(SAML, ResponseXSS.Target.ISSUER, payload);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        // First Issuer in document order (the Response-level one).
        Element issuer = (Element) doc.getElementsByTagNameNS("*", "Issuer").item(0);
        assertEquals(payload, issuer.getTextContent());
    }

    @Test
    void nameIDTextContentIsReplaced() throws Exception {
        String payload = "<svg onload=alert(1)>";
        String out = ResponseXSS.apply(SAML, ResponseXSS.Target.NAMEID, payload);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        Element nameID = (Element) doc.getElementsByTagNameNS("*", "NameID").item(0);
        assertEquals(payload, nameID.getTextContent());
    }

    @Test
    void audienceTextContentIsReplaced() throws Exception {
        String payload = "javascript:alert(1)";
        String out = ResponseXSS.apply(SAML, ResponseXSS.Target.AUDIENCE, payload);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        Element audience = (Element) doc.getElementsByTagNameNS("*", "Audience").item(0);
        assertEquals(payload, audience.getTextContent());
    }

    @Test
    void throwsWhenTargetElementMissing() {
        String noSubject = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class,
                () -> ResponseXSS.apply(noSubject, ResponseXSS.Target.NAMEID, "x"));
    }

    @Test
    void throwsWhenPayloadNull() {
        assertThrows(IllegalArgumentException.class,
                () -> ResponseXSS.apply(SAML, ResponseXSS.Target.DESTINATION, null));
    }
}

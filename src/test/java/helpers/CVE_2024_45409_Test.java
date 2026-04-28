package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CVE_2024_45409_Test {

    /// Verifies the ruby-saml bypass payload prepends an unsigned evil Assertion
    /// before the signed one and leaves the original signature untouched.
    @Test
    void prependsUnsignedEvilAssertionBeforeSignedOriginal() throws Exception {
        String input = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                  <saml:Assertion ID="a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                    <saml:Issuer>https://idp.example.com</saml:Issuer>
                    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                      <ds:SignedInfo/>
                      <ds:SignatureValue>FAKE</ds:SignatureValue>
                    </ds:Signature>
                    <saml:Subject>
                      <saml:NameID>user@example.com</saml:NameID>
                    </saml:Subject>
                  </saml:Assertion>
                </samlp:Response>
                """;

        String out = CVE_2024_45409.apply(input);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        NodeList assertions = doc.getElementsByTagNameNS("*", "Assertion");
        assertEquals(2, assertions.getLength(),
                "expected evil assertion prepended before original");

        Element evil = (Element) assertions.item(0);
        Element original = (Element) assertions.item(1);

        assertEquals("a1_evil", evil.getAttribute("ID"),
                "evil assertion ID should be original + _evil");
        assertEquals("a1", original.getAttribute("ID"),
                "original assertion ID should be preserved");

        assertFalse(hasDirectChild(evil, "Signature"),
                "evil assertion must have its signature removed");
        assertTrue(hasDirectChild(original, "Signature"),
                "original assertion should retain its signature");
    }

    private static boolean hasDirectChild(Element parent, String localName) {
        NodeList kids = parent.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            Node n = kids.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && localName.equals(n.getLocalName())) {
                return true;
            }
        }
        return false;
    }
}

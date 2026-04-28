package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DigestTamperTest {

    private static final String SAML_WITH_TWO_DIGESTS = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">
              <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                  <ds:Reference URI="#r1">
                    <ds:DigestValue>ABCDEF==</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>SIG1</ds:SignatureValue>
              </ds:Signature>
              <saml:Assertion ID="a1">
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <ds:SignedInfo>
                    <ds:Reference URI="#a1">
                      <ds:DigestValue>zzzzzz==</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>SIG2</ds:SignatureValue>
                </ds:Signature>
              </saml:Assertion>
            </samlp:Response>
            """;

    @Test
    void flipsEveryDigestValueButLeavesSignatureStructureIntact() throws Exception {
        String out = DigestTamper.apply(SAML_WITH_TWO_DIGESTS);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        NodeList digests = doc.getElementsByTagNameNS("*", "DigestValue");
        assertEquals(2, digests.getLength());
        assertEquals("BBCDEF==", ((Element) digests.item(0)).getTextContent().trim(),
                "first char 'A' should flip to 'B'");
        assertEquals("azzzzz==", ((Element) digests.item(1)).getTextContent().trim(),
                "first char 'z' should wrap to 'a'");

        // Signature elements and SignatureValues must still exist unchanged
        NodeList sigs = doc.getElementsByTagNameNS("*", "Signature");
        assertEquals(2, sigs.getLength(), "both Signature elements must be preserved");

        NodeList sigValues = doc.getElementsByTagNameNS("*", "SignatureValue");
        assertEquals("SIG1", ((Element) sigValues.item(0)).getTextContent().trim());
        assertEquals("SIG2", ((Element) sigValues.item(1)).getTextContent().trim());
    }

    @Test
    void resultDiffersFromInput() throws Exception {
        String out = DigestTamper.apply(SAML_WITH_TWO_DIGESTS);
        assertNotEquals(SAML_WITH_TWO_DIGESTS, out);
        // Tampered digests present, originals absent
        assertTrue(out.contains("BBCDEF"));
        assertTrue(out.contains("azzzzz"));
    }

    @Test
    void throwsWhenNoDigestValuePresent() {
        String unsigned = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class, () -> DigestTamper.apply(unsigned));
    }
}

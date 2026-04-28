package helpers;

import org.apache.xml.security.Init;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.cert.X509Certificate;

/// Encrypts a plaintext <saml:Assertion> into a <saml:EncryptedAssertion>
/// using the SP's public certificate.
///
/// Algorithm selection (in priority order):
///   1. Algorithms read from an existing <EncryptedAssertion> in the same
///      document — mirrors exactly what the SP already decrypted successfully.
///   2. Hardcoded fallbacks: AES-256-CBC (data) + RSA-OAEP (key wrap).
///
/// The cert itself only carries the RSA public key — it does not specify
/// preferred algorithms. SP metadata *can* include <md:EncryptionMethod>
/// hints, but most real-world metadata omits them.
public class AssertionEncryptor {

    /// Controls how the recipient certificate is identified inside the
    /// EncryptedKey's KeyInfo element.
    public enum KeyInfoStyle {
        /// Embeds the full DER-encoded certificate (verbose but unambiguous).
        FULL_CERT("Full X509Certificate"),
        /// Embeds only the issuer DN + serial number (compact; matches what
        /// most real IdPs produce and what strict SPs expect).
        ISSUER_SERIAL("X509IssuerSerial");

        private final String label;
        KeyInfoStyle(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String XENC_NS = "http://www.w3.org/2001/04/xmlenc#";

    static final String DEFAULT_DATA_ALG = XMLCipher.AES_256;    // aes256-cbc
    static final String DEFAULT_KEY_ALG  = XMLCipher.RSA_OAEP;   // rsa-oaep-mgf1p

    static {
        Init.init();
    }

    /// Encrypt the first plaintext <saml:Assertion> found in {@code samlMessage}.
    /// Algorithms are read from any existing <EncryptedAssertion> in the same
    /// document; falls back to AES-256-CBC + RSA-OAEP if none is present.
    /// {@code issuerNameOverride} is the raw X509IssuerName string captured from the
    /// original EncryptedAssertion in the document (preserving the IdP's exact DN format).
    /// Pass {@code null} to fall back to Java's RFC 2253 serialization.
    public static String encrypt(String samlMessage, X509Certificate recipientCert,
                                 KeyInfoStyle keyInfoStyle, String issuerNameOverride)
            throws Exception {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
        if (assertions.getLength() == 0) {
            throw new IllegalArgumentException(
                "No plaintext <saml:Assertion> found to encrypt. " +
                "Add one first — edit the XML directly or inject a plaintext assertion.");
        }
        Element assertion = (Element) assertions.item(0);
        Node parent = assertion.getParentNode();

        // Detect algorithms from any existing EncryptedAssertion in this document.
        String dataAlg = detectDataAlgorithm(doc);
        String keyAlg  = detectKeyAlgorithm(doc);

        // AES key size must match the algorithm URI.
        int keyBits = dataAlg.contains("aes128") ? 128 : dataAlg.contains("aes192") ? 192 : 256;
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(keyBits);
        SecretKey sessionKey = kg.generateKey();

        // Wrap the session key with the SP's RSA public key.
        XMLCipher keyCipher = XMLCipher.getInstance(keyAlg);
        keyCipher.init(XMLCipher.WRAP_MODE, recipientCert.getPublicKey());
        EncryptedKey encryptedKey = keyCipher.encryptKey(doc, sessionKey);

        // Add the recipient cert to the EncryptedKey's KeyInfo.
        KeyInfo encKeyInfo = new KeyInfo(doc);
        X509Data x509Data = new X509Data(doc);
        if (keyInfoStyle == KeyInfoStyle.ISSUER_SERIAL) {
            XMLX509IssuerSerial is = (issuerNameOverride != null && !issuerNameOverride.isBlank())
                ? new XMLX509IssuerSerial(doc, issuerNameOverride, recipientCert.getSerialNumber())
                : new XMLX509IssuerSerial(doc, recipientCert);
            x509Data.add(is);
        } else {
            x509Data.addCertificate(recipientCert);
        }
        encKeyInfo.add(x509Data);
        encryptedKey.setKeyInfo(encKeyInfo);

        // Set up the data cipher and link the EncryptedKey into its KeyInfo.
        XMLCipher dataCipher = XMLCipher.getInstance(dataAlg);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);
        KeyInfo dataKeyInfo = new KeyInfo(doc);
        dataKeyInfo.add(encryptedKey);
        dataCipher.getEncryptedData().setKeyInfo(dataKeyInfo);

        // Encrypt — assertion is removed from the DOM; xenc:EncryptedData takes its place.
        dataCipher.doFinal(doc, assertion, false);

        // Add <DigestMethod Algorithm="sha1"/> inside EncryptedKey's EncryptionMethod
        // to match the format real IdPs produce (explicit SHA-1 declaration for RSA-OAEP).
        String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
        NodeList encKeys = doc.getElementsByTagNameNS(XENC_NS, "EncryptedKey");
        if (encKeys.getLength() > 0) {
            Element encKeyEl = (Element) encKeys.item(0);
            NodeList methods = encKeyEl.getElementsByTagNameNS(XENC_NS, "EncryptionMethod");
            if (methods.getLength() > 0) {
                Element method = (Element) methods.item(0);
                Element digestMethod = doc.createElementNS(DSIG_NS, "ds:DigestMethod");
                digestMethod.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:ds", DSIG_NS);
                digestMethod.setAttribute("Algorithm", DSIG_NS + "sha1");
                method.appendChild(digestMethod);
            }
        }

        // Wrap the EncryptedData in <EncryptedAssertion xmlns="...saml...">.
        // Using the default namespace (no prefix) avoids undeclared-prefix serialization bugs
        // in the Xerces XMLSerializer, and matches the format real IdPs produce.
        Element encData = firstChildElement(parent, XENC_NS, "EncryptedData");
        if (encData == null) {
            throw new IllegalStateException(
                "Encryption produced no EncryptedData element — unexpected XMLCipher behaviour.");
        }
        Element wrapper = doc.createElementNS(SAML_NS, "EncryptedAssertion");
        wrapper.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", SAML_NS);
        parent.replaceChild(wrapper, encData);
        wrapper.appendChild(encData);

        // Strip &#xd; carriage-return entities that the Xerces XMLSerializer inserts
        // as Windows line endings inside base64 text nodes; real IdPs omit them.
        return xmlHelpers.getString(doc).replace("&#xd;", "");
    }

    /// Read the data-encryption algorithm URI from the first existing
    /// <xenc:EncryptedData>/<xenc:EncryptionMethod> in the document.
    private static String detectDataAlgorithm(Document doc) {
        NodeList methods = doc.getElementsByTagNameNS(XENC_NS, "EncryptionMethod");
        for (int i = 0; i < methods.getLength(); i++) {
            Element m = (Element) methods.item(i);
            // Data-level EncryptionMethod is a direct child of EncryptedData.
            if ("EncryptedData".equals(m.getParentNode().getLocalName())) {
                String alg = m.getAttribute("Algorithm");
                if (!alg.isBlank()) return alg;
            }
        }
        return DEFAULT_DATA_ALG;
    }

    /// Read the key-transport algorithm URI from the first existing
    /// <xenc:EncryptedKey>/<xenc:EncryptionMethod> in the document.
    private static String detectKeyAlgorithm(Document doc) {
        NodeList methods = doc.getElementsByTagNameNS(XENC_NS, "EncryptionMethod");
        for (int i = 0; i < methods.getLength(); i++) {
            Element m = (Element) methods.item(i);
            if ("EncryptedKey".equals(m.getParentNode().getLocalName())) {
                String alg = m.getAttribute("Algorithm");
                if (!alg.isBlank()) return alg;
            }
        }
        return DEFAULT_KEY_ALG;
    }

    private static Element firstChildElement(Node parent, String ns, String localName) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && ns.equals(n.getNamespaceURI())
                    && localName.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private AssertionEncryptor() {}
}

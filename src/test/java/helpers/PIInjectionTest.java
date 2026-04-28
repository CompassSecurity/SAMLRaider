package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PIInjectionTest {

    private static final String SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
              <saml:Assertion ID="a1">
                <saml:Subject><saml:NameID>admin@victim.com</saml:NameID></saml:Subject>
              </saml:Assertion>
            </samlp:Response>
            """;

    private static Element firstNameID(String xml) throws Exception {
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(xml);
        return (Element) doc.getElementsByTagNameNS("*", "NameID").item(0);
    }

    private static int piChildCount(Element el) {
        int n = 0;
        NodeList kids = el.getChildNodes();
        for (int i = 0; i < kids.getLength(); i++) {
            if (kids.item(i).getNodeType() == Node.PROCESSING_INSTRUCTION_NODE) n++;
        }
        return n;
    }

    @Test
    void beforeAtSplitsAroundAt() throws Exception {
        String out = PIInjection.apply(SAML, PIInjection.Position.BEFORE_AT);
        Element nameID = firstNameID(out);
        assertEquals(1, piChildCount(nameID));
        Node firstChild = nameID.getFirstChild();
        assertEquals("admin", firstChild.getTextContent());
        assertEquals(Node.PROCESSING_INSTRUCTION_NODE, firstChild.getNextSibling().getNodeType());
        assertEquals("@victim.com", firstChild.getNextSibling().getNextSibling().getTextContent());
        // Aggregated text content should still equal the original, since PI has no value
        assertEquals("admin@victim.com", nameID.getTextContent());
    }

    @Test
    void prependPutsPIFirst() throws Exception {
        String out = PIInjection.apply(SAML, PIInjection.Position.PREPEND);
        Element nameID = firstNameID(out);
        assertEquals(Node.PROCESSING_INSTRUCTION_NODE, nameID.getFirstChild().getNodeType());
        assertEquals("admin@victim.com", nameID.getLastChild().getTextContent());
    }

    @Test
    void appendPutsPILast() throws Exception {
        String out = PIInjection.apply(SAML, PIInjection.Position.APPEND);
        Element nameID = firstNameID(out);
        assertEquals(Node.PROCESSING_INSTRUCTION_NODE, nameID.getLastChild().getNodeType());
        assertTrue(nameID.getFirstChild().getNodeType() == Node.TEXT_NODE);
    }

    @Test
    void throwsWhenNoNameID() {
        String noSubject = """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1"/>
                """;
        assertThrows(IllegalArgumentException.class, () ->
                PIInjection.apply(noSubject, PIInjection.Position.BEFORE_AT));
    }
}

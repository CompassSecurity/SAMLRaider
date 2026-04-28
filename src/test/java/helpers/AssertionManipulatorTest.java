package helpers;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AssertionManipulatorTest {

    /// Fixture: every element that extendValidity should touch is present —
    /// Conditions has NotBefore + NotOnOrAfter, SubjectConfirmationData has NotOnOrAfter,
    /// AuthnStatement has SessionNotOnOrAfter, and StatusCode is a failure value.
    private static final String SAML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
              </samlp:Status>
              <saml:Assertion ID="a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
                <saml:Subject>
                  <saml:NameID>user@example.com</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2024-01-01T00:05:00Z"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T00:05:00Z">
                  <saml:AudienceRestriction>
                    <saml:Audience>https://sp.example.com</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z" SessionNotOnOrAfter="2024-01-01T00:05:00Z"/>
              </saml:Assertion>
            </samlp:Response>
            """;

    @Test
    void forceStatusSuccessRewritesStatusCode() throws Exception {
        String out = AssertionManipulator.forceStatusSuccess(SAML);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        NodeList codes = doc.getElementsByTagNameNS("*", "StatusCode");
        assertEquals(1, codes.getLength());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success",
                ((Element) codes.item(0)).getAttribute("Value"));
    }

    @Test
    void removeAudienceRestrictionKeepsConditionsElement() throws Exception {
        String out = AssertionManipulator.removeAudienceRestriction(SAML);
        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        assertEquals(0, doc.getElementsByTagNameNS("*", "AudienceRestriction").getLength(),
                "AudienceRestriction should be removed");
        assertEquals(1, doc.getElementsByTagNameNS("*", "Conditions").getLength(),
                "Conditions element itself should remain");
    }

    @Test
    void extendValidityPushesTimestampsForwardAndNotBeforeIntoPast() throws Exception {
        long before = System.currentTimeMillis();
        String out = AssertionManipulator.extendValidity(SAML, 24);
        long after = System.currentTimeMillis();

        Document doc = new XMLHelpers().getXMLDocumentOfSAMLMessage(out);

        // Tolerance absorbs scheduling jitter between the before/after timestamps
        // captured around the call and the wall clock read inside extendValidity.
        final long toleranceMs = 2000;

        int futureChecked = 0;
        int pastChecked = 0;

        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element el = (Element) all.item(i);

            for (String attr : new String[]{"NotOnOrAfter", "SessionNotOnOrAfter"}) {
                if (el.hasAttribute(attr)) {
                    long ts = Instant.parse(el.getAttribute(attr)).toEpochMilli();
                    long min = before + 24L * 3_600_000L - toleranceMs;
                    long max = after  + 24L * 3_600_000L + toleranceMs;
                    assertTrue(ts >= min && ts <= max,
                            attr + " out of expected +24h window: " + el.getAttribute(attr));
                    futureChecked++;
                }
            }

            if (el.hasAttribute("NotBefore")) {
                long ts = Instant.parse(el.getAttribute("NotBefore")).toEpochMilli();
                long min = before - 3_600_000L - toleranceMs;
                long max = after  - 3_600_000L + toleranceMs;
                assertTrue(ts >= min && ts <= max,
                        "NotBefore out of expected -1h window: " + el.getAttribute("NotBefore"));
                pastChecked++;
            }
        }

        assertEquals(3, futureChecked,
                "expected 3 forward-shifted timestamps (Conditions/@NotOnOrAfter, SubjectConfirmationData/@NotOnOrAfter, AuthnStatement/@SessionNotOnOrAfter)");
        assertEquals(1, pastChecked,
                "expected 1 backward-shifted timestamp (Conditions/@NotBefore)");
    }
}

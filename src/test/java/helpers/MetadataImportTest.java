package helpers;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MetadataImportTest {

    private static final String METADATA = """
            <?xml version="1.0"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                                 entityID="https://idp.example.com/metadata">
              <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA SIGNING CERT</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:KeyDescriptor use="encryption">
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>BBBB ENC CERT</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
                <md:KeyDescriptor>
                  <ds:KeyInfo><ds:X509Data><ds:X509Certificate>CCCC UNTYPED</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>
            """;

    @Test
    void extractsAllCertificatesWithUseAttribute() throws Exception {
        List<MetadataImport.Entry> entries = MetadataImport.extract(METADATA);
        assertEquals(3, entries.size());

        assertEquals("signing", entries.get(0).use());
        // Whitespace inside the certificate body is stripped for downstream import.
        assertEquals("AAAASIGNINGCERT", entries.get(0).base64Der());

        assertEquals("encryption", entries.get(1).use());
        assertEquals("BBBBENCCERT", entries.get(1).base64Der());

        // No use attribute → empty string, as documented.
        assertEquals("", entries.get(2).use());
        assertEquals("CCCCUNTYPED", entries.get(2).base64Der());
    }

    @Test
    void returnsEmptyListWhenNoKeyDescriptor() throws Exception {
        String barren = """
                <?xml version="1.0"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>
                """;
        List<MetadataImport.Entry> entries = MetadataImport.extract(barren);
        assertTrue(entries.isEmpty());
    }
}

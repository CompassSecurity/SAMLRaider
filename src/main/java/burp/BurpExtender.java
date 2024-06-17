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
import helpers.Flags;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import livetesting.LiveTestingTab;

import static java.util.Objects.requireNonNull;

public class BurpExtender implements BurpExtension, HttpRequestEditorProvider {

    public static MontoyaApi api;

    private CertificateTab certificateTab;
    private CertificateTabController certificateTabController;
    private SAMLHighlighter samlHighlighter;

    @Override
    public void initialize(MontoyaApi api) {
        BurpExtender.api = api;

        api.extension().setName("SAML Raider");

        certificateTab = new CertificateTab();
        certificateTabController = new CertificateTabController(certificateTab);
        certificateTab.setCertificateTabController(certificateTabController);
        api.userInterface().registerSuiteTab(certificateTabController.getTabCaption(), certificateTabController.getUiComponent());

        if (Flags.DEBUG) {
            var liveTestingTab = new LiveTestingTab();
            api.userInterface().registerSuiteTab(liveTestingTab.caption(), liveTestingTab);
        }

        this.samlHighlighter = new SAMLHighlighter(this.certificateTab::getSamlRequestParameterName, this.certificateTab::getSamlResponseParameterName);
        api.http().registerHttpHandler(samlHighlighter);

        api.userInterface().registerHttpRequestEditorProvider(this);

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
        return new SamlTabController(creationContext.editorMode() == EditorMode.DEFAULT, certificateTabController);
    }

}

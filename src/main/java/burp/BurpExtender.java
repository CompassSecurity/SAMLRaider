package burp;

import gui.CertificateTab;

import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.io.PrintWriter;

import application.CertificateTabController;
import application.SAMLHighlighter;
import application.SamlTabController;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	private IBurpExtenderCallbacks callbacks;
	private CertificateTab certificateTab;
	private CertificateTabController certificateTabController;
	private SAMLHighlighter samlHighlighter = new SAMLHighlighter();


	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

		this.callbacks = callbacks;
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println("SAML Raider v 1.2.5");
		stdout.println("Modified by Protect7 GmbH");
		stdout.println("- Apply XSW - Match and replace added");
		stdout.println("- Bug Fix XSW1 and XSW2");
		stdout.println("- XSW9 Attack added");
		stdout.println("- XXE and XLST Attack added");
		stdout.println("- Text Editor replaced with ITextEditor (search possibility)");
		stdout.println("- SAMLRequest and SAMLResponse Param Name can be specified in Cert Tab");

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

		callbacks.setExtensionName("SAML Raider");

		certificateTab = new CertificateTab();
		callbacks.customizeUiComponent(certificateTab);

		certificateTabController = new CertificateTabController(certificateTab);
		certificateTab.setCertificateTabController(certificateTabController);
		callbacks.addSuiteTab(certificateTabController);
		
		callbacks.registerMessageEditorTabFactory(this);
		
		callbacks.registerHttpListener(samlHighlighter);
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		SamlTabController samlTabController = new SamlTabController(callbacks, editable, certificateTabController);
		samlHighlighter.setSamlTabController(samlTabController);
		return samlTabController; 
	}
}

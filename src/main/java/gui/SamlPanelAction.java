package gui;

import application.SamlTabController;
import helpers.CommentInjection;
import helpers.CVE_2022_41912;
import helpers.CVE_2024_45409;
import helpers.CVE_2025_23369;
import helpers.CVE_2025_25291;
import helpers.CVE_2025_25292;
import helpers.EncryptionSSRF;
import helpers.IssuerConfusion;
import helpers.PIInjection;
import helpers.SignatureRefSSRF;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.Serial;
import java.util.HashMap;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import model.BurpCertificate;
import net.miginfocom.swing.MigLayout;

public class SamlPanelAction extends JPanel {

    @Serial
    private static final long serialVersionUID = 1L;

    private SamlTabController controller;

    private final JButton btnMessageReset = new JButton("Reset Message");
    private final JButton btnFormatXml = new JButton("Format XML");

    private final JButton btnXSWHelp = new JButton("?");
    private final JComboBox<String> cmbboxXSW = new JComboBox<>();
    private final JButton btnXSWPreview = new JButton("Preview in Browser...");
    private final JButton btnMatchAndReplace = new JButton("Match and Replace");
    private final JButton btnXSWApply = new JButton("Apply XSW");

    private final JButton btnTestXXE = new JButton("Test XXE");
    private final JButton btnTestXSLT = new JButton("Test XSLT");
    private final JButton btnKeyInfoSSRF = new JButton("KeyInfo SSRF");
    private final JComboBox<SignatureRefSSRF.Mode> cmbboxSigRefMode =
            new JComboBox<>(SignatureRefSSRF.Mode.values());
    private final JButton btnSigRefSSRF = new JButton("SigRef SSRF");

    private final JComboBox<String> cmbboxCVE = new JComboBox<>();
    private final JButton btnCVEApply = new JButton("Apply CVE");
    private final JButton btnCVEHelp = new JButton("?");

    private final JComboBox<CommentInjection.Position> cmbboxCommentPos = new JComboBox<>(CommentInjection.Position.values());
    private final JButton btnCommentInject = new JButton("Inject Comment");
    private final JComboBox<PIInjection.Position> cmbboxPIPos = new JComboBox<>(PIInjection.Position.values());
    private final JButton btnPIInject     = new JButton("Inject PI");
    private final JButton btnHMACConfusion = new JButton("HMAC Confusion");
    private final JButton btnResponseXSS   = new JButton("Inject XSS");
    private final JComboBox<IssuerConfusion.Mode> cmbboxIssuerMode = new JComboBox<>(IssuerConfusion.Mode.values());
    private final JButton btnIssuerConfuse = new JButton("Confuse Issuer");

    private final JButton btnRefreshTimestamps = new JButton("Refresh Timestamps");
    private final JButton btnExtendValidity = new JButton("Extend Validity +24h");
    private final JButton btnStatusSuccess  = new JButton("Status → Success");
    private final JButton btnRemoveAudience = new JButton("Remove Audience");
    private final JButton btnDigestTamper   = new JButton("Corrupt Digest");
    private final JComboBox<helpers.AssertionEncryptor.KeyInfoStyle> cmbboxKeyInfoStyle =
            new JComboBox<>(helpers.AssertionEncryptor.KeyInfoStyle.values());
    private final JButton btnEncryptAssertion = new JButton("Encrypt Assertion");

    private final JComboBox<EncryptionSSRF.Mode> cmbboxEncMode = new JComboBox<>(EncryptionSSRF.Mode.values());
    private final JButton btnEncSSRF = new JButton("Enc SSRF");

    private final JButton btnSignatureHelp = new JButton("?");
    private final JComboBox<BurpCertificate> cmbboxCertificate = new JComboBox<>();
    private final JButton btnSignatureRemove = new JButton("Remove Signatures");
    private final JButton btnResignAssertion = new JButton("(Re-)Sign Assertion");
    private final JButton btnSendCertificate = new JButton("Store Certificate");
    private final JButton btnResignMessage = new JButton("(Re-)Sign Message");
    private final JButton btnDupeKey = new JButton("Dupe Key Confusion");

    private final JButton btnACSSpoof = new JButton("Spoof ACS URL");
    private final JButton btnMetadataImport = new JButton("Import Metadata");

    private final JLabel lblSigStatus = new JLabel();

    public SamlPanelAction() {
        initialize();
    }

    public SamlPanelAction(SamlTabController controller) {
        this.controller = controller;
        initialize();
    }

    private void initialize() {
        // --- Wire listeners ---
        btnMessageReset.addActionListener(event -> controller.resetMessage());
        btnFormatXml.addActionListener(event -> controller.formatXml());

        btnXSWHelp.addActionListener(event -> controller.showXSWHelp());
        btnXSWPreview.addActionListener(event -> controller.showXSWPreview());
        btnMatchAndReplace.addActionListener(event -> showMatchAndReplaceDialog());
        btnXSWApply.addActionListener(event -> controller.applyXSW());

        btnTestXXE.addActionListener(event ->
                OobDomainDialog.prompt(this, "XXE — OOB Domain")
                        .ifPresent(controller::applyXXE));
        btnTestXSLT.addActionListener(event ->
                XSLTPayloadDialog.prompt(this)
                        .ifPresent(sel -> controller.applyXSLT(sel.flavor(), sel.param())));
        btnKeyInfoSSRF.addActionListener(event ->
                OobDomainDialog.prompt(this, "KeyInfo SSRF — Retrieval URL")
                        .ifPresent(controller::applyKeyInfoSSRF));
        btnSigRefSSRF.addActionListener(event ->
                OobDomainDialog.prompt(this, "SigRef SSRF — URL")
                        .ifPresent(url -> controller.applySignatureRefSSRF(
                                (SignatureRefSSRF.Mode) cmbboxSigRefMode.getSelectedItem(), url)));
        btnEncSSRF.addActionListener(event ->
                OobDomainDialog.prompt(this, "Encryption SSRF — Fetch URL")
                        .ifPresent(url -> controller.applyEncryptionSSRF(
                                (EncryptionSSRF.Mode) cmbboxEncMode.getSelectedItem(), url)));

        cmbboxCVE.setModel(new DefaultComboBoxModel<>(new String[]{
                CVE_2022_41912.CVE, CVE_2024_45409.CVE, CVE_2025_23369.CVE,
                CVE_2025_25291.CVE, CVE_2025_25292.CVE }));
        btnCVEApply.addActionListener(event -> controller.applyCVE());
        btnCVEHelp.addActionListener(event -> controller.showCVEHelp());

        btnCommentInject.addActionListener(event ->
                controller.applyCommentInjection(
                        (CommentInjection.Position) cmbboxCommentPos.getSelectedItem()));
        btnPIInject.addActionListener(event ->
                controller.applyPIInjection(
                        (PIInjection.Position) cmbboxPIPos.getSelectedItem()));
        btnHMACConfusion.addActionListener(event -> controller.applyHMACConfusion());
        btnResponseXSS.addActionListener(event ->
                XSSPayloadDialog.prompt(this)
                        .ifPresent(sel -> controller.applyResponseXSS(sel.target(), sel.payload())));
        btnIssuerConfuse.addActionListener(event ->
                controller.applyIssuerConfusion(
                        (IssuerConfusion.Mode) cmbboxIssuerMode.getSelectedItem()));

        btnRefreshTimestamps.addActionListener(event -> controller.applyRefreshTimestamps());
        btnExtendValidity.addActionListener(event -> controller.applyExtendValidity(24));
        btnStatusSuccess.addActionListener(event -> controller.applyStatusSuccess());
        btnRemoveAudience.addActionListener(event -> controller.applyRemoveAudience());
        btnDigestTamper.addActionListener(event -> controller.applyDigestTamper());
        btnEncryptAssertion.addActionListener(event -> controller.applyEncryptAssertion());

        btnACSSpoof.addActionListener(event ->
                OobDomainDialog.prompt(this, "ACS Spoof — Attacker URL")
                        .ifPresent(controller::applyACSSpoof));
        btnMetadataImport.addActionListener(event ->
                MetadataImportDialog.prompt(this).ifPresent(controller::importMetadata));

        btnSignatureHelp.addActionListener(event -> controller.showSignatureHelp());
        btnSignatureRemove.addActionListener(event -> controller.removeSignature());
        btnResignAssertion.addActionListener(event -> controller.resignAssertion());
        btnSendCertificate.addActionListener(event -> controller.sendToCertificatesTab());
        btnResignMessage.addActionListener(event -> controller.resignMessage());
        btnDupeKey.addActionListener(event -> controller.applyDupeKeyConfusion());

        // --- Layout ---

        // Top bar: message utilities, always visible
        var topBar = new JPanel(new MigLayout("insets 4 8 4 8, gap 6"));
        topBar.add(btnMessageReset);
        topBar.add(btnFormatXml);

        // Attack tabs
        var tabs = new JTabbedPane(JTabbedPane.TOP);
        tabs.addTab("Signatures", buildSignaturesTab());
        tabs.addTab("Injection",  buildInjectionTab());
        tabs.addTab("SSRF / RCE", buildSSRFTab());
        tabs.addTab("Assertion",  buildAssertionTab());
        tabs.addTab("CVE",        buildCVETab());
        tabs.addTab("XSW",        buildXSWTab());
        tabs.addTab("Request",    buildRequestTab());

        // Bottom bar: signing, always visible
        var bottomBar = new JPanel(new MigLayout("insets 6 8 6 8, gap 6, fillx"));
        bottomBar.add(sectionLabel("Certificate:"), "");
        bottomBar.add(cmbboxCertificate);
        bottomBar.add(btnResignAssertion);
        bottomBar.add(btnResignMessage);
        bottomBar.add(btnSignatureRemove);
        bottomBar.add(btnSignatureHelp, "wrap");
        bottomBar.add(new JLabel(""), "");
        bottomBar.add(btnSendCertificate, "wrap");
        lblSigStatus.setVisible(false);
        bottomBar.add(lblSigStatus, "span, wrap");

        setLayout(new BorderLayout());
        add(topBar, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);
        add(bottomBar, BorderLayout.SOUTH);
    }

    // --- Tab builders ---

    private JPanel buildSignaturesTab() {
        var p = tabPanel();
        p.add(btnHMACConfusion, "");
        p.add(btnDupeKey, "");
        p.add(btnDigestTamper, "wrap");
        return p;
    }

    private JPanel buildInjectionTab() {
        var p = tabPanel();
        p.add(cmbboxCommentPos, "");
        p.add(btnCommentInject, "wrap");
        p.add(cmbboxPIPos, "");
        p.add(btnPIInject, "wrap");
        p.add(btnResponseXSS, "wrap");
        p.add(cmbboxIssuerMode, "");
        p.add(btnIssuerConfuse, "wrap");
        return p;
    }

    private JPanel buildSSRFTab() {
        var p = tabPanel();
        p.add(btnTestXXE, "");
        p.add(btnTestXSLT, "wrap");
        p.add(btnKeyInfoSSRF, "wrap");
        p.add(cmbboxSigRefMode, "");
        p.add(btnSigRefSSRF, "wrap");
        p.add(cmbboxEncMode, "");
        p.add(btnEncSSRF, "wrap");
        return p;
    }

    private JPanel buildAssertionTab() {
        var p = tabPanel();
        p.add(btnRefreshTimestamps, "");
        p.add(btnExtendValidity, "wrap");
        p.add(btnStatusSuccess, "");
        p.add(btnRemoveAudience, "wrap");
        p.add(cmbboxKeyInfoStyle, "");
        p.add(btnEncryptAssertion, "wrap");
        return p;
    }

    private JPanel buildCVETab() {
        var p = tabPanel();
        p.add(cmbboxCVE, "");
        p.add(btnCVEApply, "");
        p.add(btnCVEHelp, "wrap");
        return p;
    }

    private JPanel buildXSWTab() {
        var p = tabPanel();
        p.add(cmbboxXSW, "");
        p.add(btnXSWApply, "");
        p.add(btnMatchAndReplace, "");
        p.add(btnXSWPreview, "");
        p.add(btnXSWHelp, "wrap");
        return p;
    }

    private JPanel buildRequestTab() {
        var p = tabPanel();
        p.add(btnACSSpoof, "wrap");
        p.add(btnMetadataImport, "wrap");
        return p;
    }

    private static JPanel tabPanel() {
        return new JPanel(new MigLayout("insets 10, gap 6 8"));
    }

    private static JLabel sectionLabel(String text) {
        var label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        return label;
    }

    // --- Public API ---

    public void setCertificateList(List<BurpCertificate> list) {
        DefaultComboBoxModel<BurpCertificate> model = new DefaultComboBoxModel<BurpCertificate>();
        for (BurpCertificate cert : list) {
            model.addElement(cert);
        }
        cmbboxCertificate.setModel(model);
    }

    public BurpCertificate getSelectedCertificate() {
        return (BurpCertificate) cmbboxCertificate.getSelectedItem();
    }

    public helpers.AssertionEncryptor.KeyInfoStyle getSelectedKeyInfoStyle() {
        return (helpers.AssertionEncryptor.KeyInfoStyle) cmbboxKeyInfoStyle.getSelectedItem();
    }

    public void setXSWList(String[] xswTypes) {
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<String>(xswTypes);
        cmbboxXSW.setModel(model);
    }

    public String getSelectedXSW() {
        return (String) cmbboxXSW.getSelectedItem();
    }

    public String getSelectedCVE() {
        return (String) cmbboxCVE.getSelectedItem();
    }

    public void setSignatureStatus(boolean stale) {
        if (stale) {
            lblSigStatus.setText("<html><b>&#9888; Stale signature</b> — forward as-is to test SP signature validation, or re-sign above</html>");
            lblSigStatus.setVisible(true);
        } else {
            lblSigStatus.setVisible(false);
        }
    }

    public void disableControls() {
        cmbboxCertificate.setEnabled(false);
        cmbboxXSW.setEnabled(false);
        btnXSWHelp.setEnabled(false);
        btnXSWPreview.setEnabled(false);
        btnMessageReset.setEnabled(false);
        btnXSWApply.setEnabled(false);
        btnSignatureHelp.setEnabled(false);
        btnSignatureRemove.setEnabled(false);
        btnResignAssertion.setEnabled(false);
        btnSendCertificate.setEnabled(false);
        btnResignMessage.setEnabled(false);
        btnMatchAndReplace.setEnabled(false);
        btnFormatXml.setEnabled(false);
        btnTestXXE.setEnabled(false);
        btnTestXSLT.setEnabled(false);
        btnKeyInfoSSRF.setEnabled(false);
        cmbboxCVE.setEnabled(false);
        btnCVEApply.setEnabled(false);
        cmbboxCommentPos.setEnabled(false);
        btnCommentInject.setEnabled(false);
        btnHMACConfusion.setEnabled(false);
        btnResponseXSS.setEnabled(false);
        btnRefreshTimestamps.setEnabled(false);
        btnExtendValidity.setEnabled(false);
        btnStatusSuccess.setEnabled(false);
        btnRemoveAudience.setEnabled(false);
        btnDigestTamper.setEnabled(false);
        cmbboxKeyInfoStyle.setEnabled(false);
        btnEncryptAssertion.setEnabled(false);
        cmbboxEncMode.setEnabled(false);
        btnEncSSRF.setEnabled(false);
        cmbboxSigRefMode.setEnabled(false);
        btnSigRefSSRF.setEnabled(false);
        cmbboxPIPos.setEnabled(false);
        btnPIInject.setEnabled(false);
        cmbboxIssuerMode.setEnabled(false);
        btnIssuerConfuse.setEnabled(false);
        btnDupeKey.setEnabled(false);
        btnACSSpoof.setEnabled(false);
        btnMetadataImport.setEnabled(false);
        this.revalidate();
    }

    public void enableControls() {
        cmbboxCertificate.setEnabled(true);
        cmbboxXSW.setEnabled(true);
        btnXSWHelp.setEnabled(true);
        btnXSWPreview.setEnabled(true);
        btnMessageReset.setEnabled(true);
        btnXSWApply.setEnabled(true);
        btnSignatureHelp.setEnabled(true);
        btnSignatureRemove.setEnabled(true);
        btnResignAssertion.setEnabled(true);
        btnSendCertificate.setEnabled(true);
        btnResignMessage.setEnabled(true);
        btnMatchAndReplace.setEnabled(true);
        btnFormatXml.setEnabled(true);
        btnTestXXE.setEnabled(true);
        btnTestXSLT.setEnabled(true);
        btnKeyInfoSSRF.setEnabled(true);
        cmbboxCVE.setEnabled(true);
        btnCVEApply.setEnabled(true);
        cmbboxCommentPos.setEnabled(true);
        btnCommentInject.setEnabled(true);
        btnHMACConfusion.setEnabled(true);
        btnResponseXSS.setEnabled(true);
        btnRefreshTimestamps.setEnabled(true);
        btnExtendValidity.setEnabled(true);
        btnStatusSuccess.setEnabled(true);
        btnRemoveAudience.setEnabled(true);
        btnDigestTamper.setEnabled(true);
        cmbboxKeyInfoStyle.setEnabled(true);
        btnEncryptAssertion.setEnabled(true);
        cmbboxEncMode.setEnabled(true);
        btnEncSSRF.setEnabled(true);
        cmbboxSigRefMode.setEnabled(true);
        btnSigRefSSRF.setEnabled(true);
        cmbboxPIPos.setEnabled(true);
        btnPIInject.setEnabled(true);
        cmbboxIssuerMode.setEnabled(true);
        btnIssuerConfuse.setEnabled(true);
        btnDupeKey.setEnabled(true);
        btnACSSpoof.setEnabled(true);
        btnMetadataImport.setEnabled(true);
        this.revalidate();
    }

    private void showMatchAndReplaceDialog() {
        HashMap<String, String> matchAndReplaceMap = controller.getMatchAndReplaceMap();

        JPanel dialogPanel = new JPanel();
        dialogPanel.setLayout(new BorderLayout());
        dialogPanel.add(new JLabel("Match and replace rules takes effect after apply XSW"), BorderLayout.NORTH);

        JPanel listPanel = new JPanel();
        JTextField matchInputText = new JTextField();
        JTextField replaceInputText = new JTextField();

        JButton addEntryButton = new JButton("➕");
        addEntryButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if (matchInputText.getText() != "" && replaceInputText.getText() != "") {
                    matchAndReplaceMap.put(matchInputText.getText(), replaceInputText.getText());
                    updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
                    SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
                }
            }
        });

        updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
        JOptionPane.showMessageDialog(this, listPanel, "Apply XSW - Match and Replace", JOptionPane.PLAIN_MESSAGE);
    }

    private void updateMatchAndReplaceList(JPanel listPanel, JTextField matchInputText, JTextField replaceInputText, JButton addEntryButton) {
        HashMap<String, String> matchAndReplaceMap = controller.getMatchAndReplaceMap();
        listPanel.setLayout(new GridBagLayout());
        listPanel.removeAll();
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0;
        c.gridy = 0;
        listPanel.add(new JLabel("Match:                                          "), c);
        c.gridx = 1;
        listPanel.add(new JLabel("Replace:                                        "), c);
        c.gridx = 0;
        c.gridy = 1;
        listPanel.add(matchInputText, c);
        c.gridx = 1;
        listPanel.add(replaceInputText, c);
        c.gridx = 2;
        listPanel.add(addEntryButton, c);

        c.gridy = 2;
        for (String matchRule : matchAndReplaceMap.keySet()) {
            c.gridx = 0;
            listPanel.add(new JLabel(matchRule), c);

            c.gridx = 1;
            listPanel.add(new JLabel(matchAndReplaceMap.get(matchRule)), c);
            JButton deleteEntryBtn = new JButton("➖");
            deleteEntryBtn.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent e) {
                    matchAndReplaceMap.remove(matchRule);
                    updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
                    SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
                }
            });
            c.gridx = 2;
            listPanel.add(deleteEntryBtn, c);
            c.gridy++;
        }
        listPanel.revalidate();
    }
}

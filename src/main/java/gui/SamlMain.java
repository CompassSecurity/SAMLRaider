package gui;

import application.SamlTabController;
import burp.BurpExtender;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.editor.RawEditor;
import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;

import static java.util.Objects.requireNonNull;

public class SamlMain extends JPanel {

    private final SamlTabController controller;

    private RawEditor textEditorAction;
    private RawEditor textEditorInformation;
    private SamlPanelAction panelAction;
    private SamlPanelInfo panelInformation;

    public SamlMain(SamlTabController controller) {
        this.controller = requireNonNull(controller, "controller");
        initializeUI();
    }

    private void initializeUI() {
        setLayout(new BorderLayout(0, 0));

        JSplitPane splitPaneAction = new JSplitPane();
        splitPaneAction.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPaneAction.setDividerSize(5);
        add(splitPaneAction, BorderLayout.CENTER);

        JPanel panelActionTop = new JPanel();
        splitPaneAction.setLeftComponent(panelActionTop);
        panelActionTop.setLayout(new BorderLayout(0, 0));
        panelAction = new SamlPanelAction(controller);
        panelActionTop.add(panelAction);

        JPanel panelActionBottom = new JPanel();
        splitPaneAction.setRightComponent(panelActionBottom);
        panelActionBottom.setLayout(new BorderLayout(0, 0));
        textEditorAction = BurpExtender.api.userInterface().createRawEditor();
        textEditorAction.setContents(ByteArray.byteArray("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>"));
        panelActionBottom.add(textEditorAction.uiComponent(), BorderLayout.CENTER);

        JSplitPane splitPaneInformation = new JSplitPane();
        splitPaneInformation.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPaneAction.setDividerSize(5);
        add(splitPaneInformation, BorderLayout.CENTER);

        JPanel panelInformationTop = new JPanel();
        splitPaneInformation.setLeftComponent((panelInformationTop));
        panelInformationTop.setLayout(new BorderLayout(0, 0));
        panelInformation = new SamlPanelInfo();
        panelInformationTop.add(panelInformation);

        JPanel panelInformationBottom = new JPanel();
        splitPaneInformation.setRightComponent(panelInformationBottom);
        panelInformationBottom.setLayout(new BorderLayout(0, 0));
        textEditorInformation = BurpExtender.api.userInterface().createRawEditor();
        textEditorInformation.setContents(ByteArray.byteArray(""));
        textEditorAction.setEditable(false);
        panelInformationBottom.add(textEditorInformation.uiComponent(), BorderLayout.CENTER);

        JTabbedPane tabbedPane = new JTabbedPane();
        add(tabbedPane);
        tabbedPane.addTab("SAML Attacks", null, splitPaneAction, "SAML Attacks");
        tabbedPane.addTab("SAML Message Info", null, splitPaneInformation, "SAML Message Info");

        this.invalidate();
        this.updateUI();
    }

    public RawEditor getTextEditorAction() {
        return textEditorAction;
    }

    public RawEditor getTextEditorInformation() {
        return textEditorInformation;
    }

    public SamlPanelAction getActionPanel() {
        return panelAction;
    }

    public SamlPanelInfo getInfoPanel() {
        return panelInformation;
    }

}

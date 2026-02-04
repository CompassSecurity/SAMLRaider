package gui;

import application.SamlTabController;
import java.awt.BorderLayout;
import java.awt.Dimension;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;

import static java.util.Objects.requireNonNull;

public class SamlMain extends JPanel {

    private final SamlTabController controller;

    private SamlXmlEditor xmlEditorAction;
    private SamlPanelAction panelAction;
    private SamlPanelInfo panelInformation;
    private SamlPanelStatus panelStatus;

    public SamlMain(SamlTabController controller) {
        this.controller = requireNonNull(controller, "controller");
        initializeUI();
    }

    private void initializeUI() {
        panelAction = new SamlPanelAction(controller);

        JPanel splitPaneActionTop = new JPanel();
        splitPaneActionTop.setLayout(new BorderLayout());
        splitPaneActionTop.setPreferredSize(new Dimension(0, 460));
        splitPaneActionTop.add(panelAction);

        xmlEditorAction = new SamlXmlEditor();
        xmlEditorAction.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>");
        xmlEditorAction.setEditable(false);

        JPanel splitPaneActionBottom = new JPanel();
        splitPaneActionBottom.setLayout(new BorderLayout());
        splitPaneActionBottom.setPreferredSize(new Dimension(0, 100));
        splitPaneActionBottom.add(xmlEditorAction, BorderLayout.CENTER);

        JSplitPane splitPaneAction = new JSplitPane();
        splitPaneAction.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPaneAction.setLeftComponent(splitPaneActionTop);
        splitPaneAction.setRightComponent(splitPaneActionBottom);
        splitPaneAction.resetToPreferredSizes();

        panelInformation = new SamlPanelInfo();

        JPanel splitPaneInformationTop = new JPanel();
        splitPaneInformationTop.setLayout(new BorderLayout());
        splitPaneInformationTop.setPreferredSize(new Dimension(0, 375));
        splitPaneInformationTop.add(panelInformation);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("SAML Attacks", null, splitPaneAction, "SAML Attacks");
        tabbedPane.addTab("SAML Message Info", null, splitPaneInformationTop, "SAML Message Info");

        panelStatus = new SamlPanelStatus();

        setLayout(new BorderLayout());
        add(tabbedPane, BorderLayout.CENTER);
        add(panelStatus, BorderLayout.SOUTH);

        invalidate();
        updateUI();
    }

    public SamlXmlEditor getXmlEditorAction() {
        return xmlEditorAction;
    }

    public SamlPanelAction getActionPanel() {
        return panelAction;
    }

    public SamlPanelInfo getInfoPanel() {
        return panelInformation;
    }

    public SamlPanelStatus getStatusPanel() {
        return panelStatus;
    }

}

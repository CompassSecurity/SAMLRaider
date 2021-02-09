package gui;

import java.awt.BorderLayout;

import javax.swing.*;

import application.SamlTabController;
import burp.ITextEditor;

public class SamlMain extends javax.swing.JPanel{
	
	private static final long serialVersionUID = 1L;
	private ITextEditor textEditorAction;
	private ITextEditor textEditorInformation;
	private SamlTabController controller;
	private SamlPanelAction panelAction;
	private SamlPanelInfo panelInformation;
	
	public SamlMain() {
		super();
		initializeUI();
	}
	
	public SamlMain(SamlTabController controller){
		super();
		this.controller = controller;
		initializeUI();
	}
	
	private void initializeUI(){
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
		textEditorAction = controller.getCallbacks().createTextEditor();
		textEditorAction.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>".getBytes());
        panelActionBottom.add(textEditorAction.getComponent(), BorderLayout.CENTER);
		
		JSplitPane splitPaneInformation = new JSplitPane();
		splitPaneInformation.setOrientation(JSplitPane.VERTICAL_SPLIT);
		splitPaneAction.setDividerSize(5);
		add(splitPaneInformation, BorderLayout.CENTER);

		JPanel panelInformationTop = new JPanel();
		splitPaneInformation.setLeftComponent((panelInformationTop));
		panelInformationTop.setLayout(new BorderLayout(0,0));
		panelInformation = new SamlPanelInfo();
		panelInformationTop.add(panelInformation);

		JPanel panelInformationBottom = new JPanel();
		splitPaneInformation.setRightComponent(panelInformationBottom);
		panelInformationBottom.setLayout(new BorderLayout(0,0));
		textEditorInformation = controller.getCallbacks().createTextEditor();
		textEditorInformation.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>".getBytes());
		textEditorAction.setEditable(false);
		panelInformationBottom.add(textEditorInformation.getComponent(), BorderLayout.CENTER);

		JTabbedPane tabbedPane = new JTabbedPane();
		add(tabbedPane);
		tabbedPane.addTab("SAML Attacks", null, splitPaneAction, "SAML Attacks");
		tabbedPane.addTab("SAML Message Info", null, splitPaneInformation, "SAML Message Info");

        this.invalidate();
        this.updateUI();
	}
	
	public ITextEditor getTextEditorAction(){
		return textEditorAction;
	}

	public ITextEditor getTextEditorInformation() { return textEditorInformation; }
	
	public SamlPanelAction getActionPanel(){
		return panelAction;
	}
	
	public SamlPanelInfo getInfoPanel(){
		return panelInformation;
	}
	
}

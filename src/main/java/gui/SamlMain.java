package gui;

import java.awt.BorderLayout;

import javax.swing.*;

import application.SamlTabController;
import burp.ITextEditor;

public class SamlMain extends javax.swing.JPanel{
	
	private static final long serialVersionUID = 1L;
	private ITextEditor textArea;
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
		
		JSplitPane splitPaneMain = new JSplitPane();
		splitPaneMain.setOrientation(JSplitPane.VERTICAL_SPLIT);
		splitPaneMain.setDividerSize(5);
		add(splitPaneMain, BorderLayout.CENTER);
		
		JPanel panelTop = new JPanel();
		splitPaneMain.setLeftComponent(panelTop);
		panelTop.setLayout(new BorderLayout(0, 0));

		panelAction = new SamlPanelAction(controller);
		panelTop.add(panelAction);
		
		panelInformation = new SamlPanelInfo();

		JPanel panelText = new JPanel();
		splitPaneMain.setRightComponent(panelText);
		panelText.setLayout(new BorderLayout(0, 0));
		
		textArea = controller.getCallbacks().createTextEditor();
		textArea.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>".getBytes());
        panelText.add(textArea.getComponent(), BorderLayout.CENTER);
		
        splitPaneMain.setDividerLocation(0.5);

		JTabbedPane tabbedPane = new JTabbedPane();
		add(tabbedPane);
		tabbedPane.addTab("SAML Attacks", null, splitPaneMain, "SAML Attacks");
		tabbedPane.addTab("SAML Message Info", null, panelInformation, "SAML Message Info");
        
        this.invalidate();
        this.updateUI();
	}
	
	public ITextEditor getTextArea(){
		return textArea;
	}
	
	public SamlPanelAction getActionPanel(){
		return panelAction;
	}
	
	public SamlPanelInfo getInfoPanel(){
		return panelInformation;
	}
	
}

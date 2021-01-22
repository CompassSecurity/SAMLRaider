package gui;

import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
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
		splitPaneMain.setResizeWeight(0.5);
		splitPaneMain.setDividerSize(5);
		add(splitPaneMain, BorderLayout.CENTER);
		
		JPanel panelTop = new JPanel();
		splitPaneMain.setLeftComponent(panelTop);
		panelTop.setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPaneTop = new JSplitPane();
		splitPaneTop.setResizeWeight(0.5);
		splitPaneTop.setDividerSize(5);
		panelTop.add(splitPaneTop);
		
		panelAction = new SamlPanelAction(controller);
		splitPaneTop.setLeftComponent(new JScrollPane(panelAction));
		
		panelInformation = new SamlPanelInfo();
		splitPaneTop.setRightComponent(new JScrollPane(panelInformation));
		
		JPanel panelText = new JPanel();
		splitPaneMain.setRightComponent(panelText);
		panelText.setLayout(new BorderLayout(0, 0));
		
		textArea = controller.getCallbacks().createTextEditor();
		textArea.setText("<SAMLRaiderFailureInInitialization></SAMLRaiderFailureInInitialization>".getBytes());
        panelText.add(textArea.getComponent(), BorderLayout.CENTER);
		
        splitPaneMain.setDividerLocation(0.5);
        splitPaneTop.setDividerLocation(0.5);
        
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

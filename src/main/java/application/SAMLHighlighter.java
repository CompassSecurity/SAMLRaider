package application;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;

public class SAMLHighlighter implements HttpHandler {
	
	private SamlTabController samlTabController;
	
	public void setSamlTabController(SamlTabController samlTabController) {
		this.samlTabController = samlTabController;
	}
	
	@Override
	public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
		if (requestToBeSent.toolSource().isFromTool(ToolType.PROXY)) {
			if(samlTabController.isEnabledFor(HttpRequestResponse.httpRequestResponse(requestToBeSent, null))){
				requestToBeSent.annotations().setHighlightColor(HighlightColor.BLUE);
			}
		}
		return RequestToBeSentAction.continueWith(requestToBeSent);
	}

	@Override
	public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
		return ResponseReceivedAction.continueWith(responseReceived);
	}
}

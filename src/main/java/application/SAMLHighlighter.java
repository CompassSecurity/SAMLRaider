package application;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

public class SAMLHighlighter implements HttpHandler {

    private final Supplier<String> samlRequestParameterNameSupplier;
    private final Supplier<String> samlResponseParameterNameSupplier;

    public SAMLHighlighter(
            Supplier<String> samlRequestParameterNameSupplier,
            Supplier<String> samlResponseParameterNameSupplier) {
        this.samlRequestParameterNameSupplier = requireNonNull(samlRequestParameterNameSupplier, "samlRequestParameterNameSupplier");
        this.samlResponseParameterNameSupplier = requireNonNull(samlResponseParameterNameSupplier, "samlResponseParameterNameSupplier");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (requestToBeSent.toolSource().isFromTool(ToolType.PROXY)) {
            var samlMessageAnalysisResult =
                    SamlMessageAnalyzer.analyze(
                            requestToBeSent,
                            this.samlRequestParameterNameSupplier.get(),
                            this.samlResponseParameterNameSupplier.get());
            if (samlMessageAnalysisResult.isSAMLMessage()) {
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

import UIKit
import WebKit

class WebViewController: UIViewController, WKScriptMessageHandler {

    private let url: URL
    private var webView: WKWebView!

    init(url: URL) {
        self.url = url
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        let config = WKWebViewConfiguration()
        config.userContentController.add(self, name: "bank")
        webView = WKWebView(frame: view.bounds, configuration: config)
        view.addSubview(webView)
        webView.load(URLRequest(url: url))
    }

    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.name == "bank" {
            let token = TokenStore().authToken() ?? ""
            webView.evaluateJavaScript("window.onToken('\(token)')")
        }
    }
}

class HelpViewController: UIViewController {

    private static let helpHTML = "<html><body><h1>Help</h1><p>Call us at 1588-0000.</p></body></html>"

    override func viewDidLoad() {
        super.viewDidLoad()
        let webView = WKWebView(frame: view.bounds)
        view.addSubview(webView)
        webView.loadHTMLString(HelpViewController.helpHTML, baseURL: nil)
    }
}

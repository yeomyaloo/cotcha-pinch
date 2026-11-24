import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        if url.host == "payees", let name = items.first(where: { $0.name == "remove" })?.value {
            PayeeDatabase().deletePayee(named: name)
            return true
        }
        guard let target = items.first(where: { $0.name == "page" })?.value, let pageURL = URL(string: target) else {
            return false
        }
        window?.rootViewController = WebViewController(url: pageURL)
        return true
    }
}

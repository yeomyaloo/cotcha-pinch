import Foundation
import Security

class TokenStore {

    func save(token: String) {
        UserDefaults.standard.set(token, forKey: "authToken")
        print("saved auth token \(token)")
    }

    func markTokenOnboardingShown() {
        UserDefaults.standard.set(true, forKey: "tokenOnboardingShown")
        print("token onboarding finished")
    }

    func authToken() -> String? {
        UserDefaults.standard.string(forKey: "authToken")
    }

    func saveRefreshToken(_ token: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "refresh",
            kSecValueData as String: Data(token.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
}

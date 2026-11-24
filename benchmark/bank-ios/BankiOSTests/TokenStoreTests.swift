import XCTest
@testable import BankiOS

final class TokenStoreTests: XCTestCase {

    func testSave() {
        UserDefaults.standard.set("test-token", forKey: "authToken")
        print("token for test: test-token")
    }
}

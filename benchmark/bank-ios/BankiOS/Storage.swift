import CryptoKit
import Foundation
import SQLite3

class PayeeDatabase {

    private var db: OpaquePointer?

    func deletePayee(named name: String) {
        sqlite3_exec(db, "DELETE FROM payees WHERE name = '\(name)'", nil, nil, nil)
    }

    func payeeName(id: Int32) -> String? {
        var statement: OpaquePointer?
        sqlite3_prepare_v2(db, "SELECT name FROM payees WHERE id = ?", -1, &statement, nil)
        sqlite3_bind_int(statement, 1, id)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW, let text = sqlite3_column_text(statement, 0) else {
            return nil
        }
        return String(cString: text)
    }
}

enum PinHasher {

    static func hash(pin: String) -> String {
        Insecure.MD5.hash(data: Data(pin.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func cacheKey(for imageURL: URL) -> String {
        Insecure.MD5.hash(data: Data(imageURL.absoluteString.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

enum PaymentConfig {
    static let clientSecret = "cs_9fQ2LxT7mBv4Kp8WnZr3"
}

import Foundation
import CryptoSwift

class Encrypter {
    private var cipher: String

    private var key: String

    init(key: String, cipher: String) {
        self.cipher = cipher
        self.key = key
    }

    func unserialize(for text: String) -> String! {
        let range = text.range(of: #"(?=\{).*(?<=\})"#, options: .regularExpression)

        if (range == nil) {
            print("ERROR: (matches) --> not matches result")

            return nil
        }

        let json = text[range!]

        return String(json)
    }

    func opensslDecrypt(data: String, method: String, key: [UInt8], options: Int = 0, iv: [UInt8]) -> String! {
        do {
            let aes = try AES(key: key, blockMode: CBC(iv: iv))
            let decryptedBytes = try data.decryptBase64(cipher: aes)
            let decryptedString = String(data: Data(_: decryptedBytes), encoding: .utf8)

            return decryptedString
        } catch {
            print("ERROR: (opensslDecrypt) --> \(error)")

            return nil
        }
    }

    func decrypt(payload: String, unserialize: Bool = true) -> String! {
        let payloadArray = self.getJsonPayload(payload: payload)

        print("INFO: (payloadArray) --> \(payloadArray)")

        let keyBytes = [UInt8](self.key.utf8)
        let base64Data = Data(base64Encoded: payloadArray["iv"]!)!
        let ivBytes = base64Data.bytes

        let decryptedString = self.opensslDecrypt(data: payloadArray["value"]!, method: self.cipher, key: keyBytes, options: 0, iv: ivBytes) as String

        print("INFO: (decryptedString) --> \(decryptedString)")

        let decryptedJson = self.unserialize(for: decryptedString)

        print("INFO: (decryptedJson) --> \(decryptedJson!)")

        return decryptedJson
    }

    func getJsonPayload(payload: String) -> [String: String] {
        let payloadData = Data(base64Encoded: payload)!

        do {
            let payloadArray = try JSONSerialization.jsonObject(with: payloadData, options: []) as! [String: String]

            if (!self.validPayload(payload: payloadArray)) {
                throw NSError(domain: "Payload invalid", code: 4001)
            }

            if (!self.validPayload(payload: payloadArray)) {
                throw NSError(domain: "MAC invalid", code: 4002)
            }

            return payloadArray
        } catch {
            print("ERROR: (getJsonPayload) --> \(error)")

            return [String: String]()
        }
    }

    func validPayload(payload: [String: String]) -> Bool {
        if (payload["iv"] == nil || payload["value"] == nil || payload["mac"] == nil) {
            return false
        }

        return true
    }

    func validMAC(payload: [String: String]) -> Bool {
        return true
    }
}

import Darwin

private let maximumInputBytes: Int64 = 1 * 1024 * 1024

private enum ProbeError: Error {
    case invalidInput(String)
}

private enum JSONValue {
    case null
    case bool(Bool)
    case number(String)
    case string(String)
    case array([JSONValue])
    case object([(String, JSONValue)])
}

private struct JSONParser {
    private let bytes: [UInt8]
    private var index: Int = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func parse() throws -> JSONValue {
        skipWhitespace()
        let value = try parseValue(depth: 0)
        skipWhitespace()
        guard index == bytes.count else { throw ProbeError.invalidInput("trailing JSON data") }
        return value
    }

    private mutating func parseValue(depth: Int) throws -> JSONValue {
        guard depth <= 64, index < bytes.count else { throw ProbeError.invalidInput("invalid JSON depth or end of input") }
        switch bytes[index] {
        case 0x6e:
            try consumeKeyword("null")
            return .null
        case 0x66:
            try consumeKeyword("false")
            return .bool(false)
        case 0x74:
            try consumeKeyword("true")
            return .bool(true)
        case 0x22:
            return .string(try parseString())
        case 0x5b:
            return try parseArray(depth: depth + 1)
        case 0x7b:
            return try parseObject(depth: depth + 1)
        case 0x2d, 0x30...0x39:
            return .number(try parseNumber())
        default:
            throw ProbeError.invalidInput("invalid JSON value")
        }
    }

    private mutating func parseArray(depth: Int) throws -> JSONValue {
        index += 1
        skipWhitespace()
        var values: [JSONValue] = []
        if consume(0x5d) { return .array(values) }
        while true {
            values.append(try parseValue(depth: depth))
            skipWhitespace()
            if consume(0x5d) { return .array(values) }
            guard consume(0x2c) else { throw ProbeError.invalidInput("array separator missing") }
            skipWhitespace()
        }
    }

    private mutating func parseObject(depth: Int) throws -> JSONValue {
        index += 1
        skipWhitespace()
        var entries: [(String, JSONValue)] = []
        var keyBytes: [[UInt8]] = []
        if consume(0x7d) { return .object(entries) }
        while true {
            guard index < bytes.count, bytes[index] == 0x22 else { throw ProbeError.invalidInput("object key is not a string") }
            let key = try parseString()
            let rawKey = Array(key.utf8)
            guard !keyBytes.contains(where: { $0 == rawKey }) else { throw ProbeError.invalidInput("duplicate object key") }
            keyBytes.append(rawKey)
            skipWhitespace()
            guard consume(0x3a) else { throw ProbeError.invalidInput("object separator missing") }
            skipWhitespace()
            entries.append((key, try parseValue(depth: depth)))
            skipWhitespace()
            if consume(0x7d) { return .object(entries) }
            guard consume(0x2c) else { throw ProbeError.invalidInput("object separator missing") }
            skipWhitespace()
        }
    }

    private mutating func parseString() throws -> String {
        guard consume(0x22) else { throw ProbeError.invalidInput("string opening quote missing") }
        var output: [UInt8] = []
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if byte == 0x22 {
                let value = String(decoding: output, as: UTF8.self)
                guard Array(value.utf8) == output else { throw ProbeError.invalidInput("string is not valid UTF-8") }
                return value
            }
            if byte == 0x5c {
                guard index < bytes.count else { throw ProbeError.invalidInput("truncated string escape") }
                let escape = bytes[index]
                index += 1
                switch escape {
                case 0x22, 0x5c, 0x2f: output.append(escape)
                case 0x62: output.append(0x08)
                case 0x66: output.append(0x0c)
                case 0x6e: output.append(0x0a)
                case 0x72: output.append(0x0d)
                case 0x74: output.append(0x09)
                case 0x75:
                    let first = try parseHexQuad()
                    var scalar = first
                    if first >= 0xd800 && first <= 0xdbff {
                        guard consume(0x5c), consume(0x75) else { throw ProbeError.invalidInput("unpaired high surrogate") }
                        let second = try parseHexQuad()
                        guard second >= 0xdc00 && second <= 0xdfff else { throw ProbeError.invalidInput("invalid low surrogate") }
                        scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                    } else if first >= 0xdc00 && first <= 0xdfff {
                        throw ProbeError.invalidInput("unpaired low surrogate")
                    }
                    guard let unicodeScalar = UnicodeScalar(scalar) else { throw ProbeError.invalidInput("invalid Unicode scalar") }
                    output.append(contentsOf: String(unicodeScalar).utf8)
                default:
                    throw ProbeError.invalidInput("unknown string escape")
                }
            } else {
                guard byte >= 0x20 else { throw ProbeError.invalidInput("unescaped control character") }
                output.append(byte)
            }
        }
        throw ProbeError.invalidInput("unterminated string")
    }

    private mutating func parseHexQuad() throws -> UInt32 {
        guard index + 4 <= bytes.count else { throw ProbeError.invalidInput("truncated Unicode escape") }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = bytes[index]
            index += 1
            let digit: UInt32
            switch byte {
            case 0x30...0x39: digit = UInt32(byte - 0x30)
            case 0x41...0x46: digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66: digit = UInt32(byte - 0x61 + 10)
            default: throw ProbeError.invalidInput("invalid Unicode escape")
            }
            value = (value << 4) | digit
        }
        return value
    }

    private mutating func parseNumber() throws -> String {
        let start = index
        _ = consume(0x2d)
        if consume(0x30) {
            if index < bytes.count, bytes[index] >= 0x30 && bytes[index] <= 0x39 {
                throw ProbeError.invalidInput("number has leading zero")
            }
        } else {
            guard consumeDigits(minimum: 1) else { throw ProbeError.invalidInput("number integer is missing") }
        }
        if consume(0x2e) {
            guard consumeDigits(minimum: 1) else { throw ProbeError.invalidInput("number fraction is missing") }
        }
        if index < bytes.count, bytes[index] == 0x65 || bytes[index] == 0x45 {
            index += 1
            _ = consume(0x2b) || consume(0x2d)
            guard consumeDigits(minimum: 1) else { throw ProbeError.invalidInput("number exponent is missing") }
        }
        return String(decoding: bytes[start..<index], as: UTF8.self)
    }

    private mutating func consumeDigits(minimum: Int) -> Bool {
        let start = index
        while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 { index += 1 }
        return index - start >= minimum
    }

    private mutating func consumeKeyword(_ keyword: String) throws {
        let keywordBytes = Array(keyword.utf8)
        guard index + keywordBytes.count <= bytes.count, Array(bytes[index..<(index + keywordBytes.count)]) == keywordBytes else {
            throw ProbeError.invalidInput("invalid JSON keyword")
        }
        index += keywordBytes.count
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }

    private mutating func skipWhitespace() {
        while index < bytes.count, bytes[index] == 0x20 || bytes[index] == 0x09 || bytes[index] == 0x0a || bytes[index] == 0x0d {
            index += 1
        }
    }
}

private func compareUtf16(_ left: String, _ right: String) -> Bool {
    let leftUnits = Array(left.utf16)
    let rightUnits = Array(right.utf16)
    for index in 0..<min(leftUnits.count, rightUnits.count) {
        if leftUnits[index] != rightUnits[index] { return leftUnits[index] < rightUnits[index] }
    }
    return leftUnits.count < rightUnits.count
}

private func hex(_ value: UInt32, width: Int) -> String {
    let digits = Array("0123456789abcdef")
    var value = value
    var output = ""
    repeat {
        output = String(digits[Int(value & 0xf)]) + output
        value >>= 4
    } while value != 0
    while output.count < width { output = "0" + output }
    return output
}

private func canonicalString(_ value: String) -> String {
    var result = "\""
    for scalar in value.unicodeScalars {
        switch scalar.value {
        case 0x08: result += "\\b"
        case 0x09: result += "\\t"
        case 0x0a: result += "\\n"
        case 0x0c: result += "\\f"
        case 0x0d: result += "\\r"
        case 0x22: result += "\\\""
        case 0x5c: result += "\\\\"
        case 0x00...0x1f: result += "\\u" + hex(scalar.value, width: 4)
        default: result += String(scalar)
        }
    }
    return result + "\""
}

private func canonicalNumber(_ token: String) throws -> String {
    var text = token
    var negative = false
    if text.first == "-" {
        negative = true
        text.removeFirst()
    }
    guard !text.isEmpty else { throw ProbeError.invalidInput("empty number") }
    let exponentParts = text.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "e" || $0 == "E" })
    guard exponentParts.count <= 2 else { throw ProbeError.invalidInput("invalid number exponent") }
    let mantissa = String(exponentParts[0])
    let exponent = exponentParts.count == 2 ? (Int(exponentParts[1]) ?? 0) : 0
    guard exponent >= -10000 && exponent <= 10000 else { throw ProbeError.invalidInput("number exponent is too large") }
    let mantissaParts = mantissa.split(separator: ".", omittingEmptySubsequences: false)
    guard mantissaParts.count <= 2 else { throw ProbeError.invalidInput("invalid number fraction") }
    let integerPart = String(mantissaParts[0])
    let fractionalPart = mantissaParts.count == 2 ? String(mantissaParts[1]) : ""
    var digits = Array((integerPart + fractionalPart).utf8)
    guard !digits.isEmpty, digits.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { throw ProbeError.invalidInput("invalid number digits") }
    var decimalPoint = integerPart.count + exponent
    while digits.count > 1 && digits[0] == 0x30 {
        digits.removeFirst()
        decimalPoint -= 1
    }
    while digits.count > 1 && digits.last == 0x30 { digits.removeLast() }
    guard digits.contains(where: { $0 != 0x30 }) else { return "0" }
    let scientificExponent = decimalPoint - 1
    let useScientific = scientificExponent < -6 || scientificExponent >= 21
    var body: String
    if useScientific {
        body = String(decoding: [digits[0]], as: UTF8.self)
        if digits.count > 1 { body += "." + String(decoding: digits[1...], as: UTF8.self) }
        body += "e" + (scientificExponent >= 0 ? "+" : "") + String(scientificExponent)
    } else if decimalPoint <= 0 {
        body = "0." + String(repeating: "0", count: Int(-decimalPoint)) + String(decoding: digits, as: UTF8.self)
    } else if decimalPoint >= digits.count {
        body = String(decoding: digits, as: UTF8.self) + String(repeating: "0", count: decimalPoint - digits.count)
    } else {
        body = String(decoding: digits[..<decimalPoint], as: UTF8.self) + "." + String(decoding: digits[decimalPoint...], as: UTF8.self)
    }
    return negative ? "-" + body : body
}

private func canonicalJson(_ value: JSONValue) throws -> String {
    switch value {
    case .null: return "null"
    case .bool(let value): return value ? "true" : "false"
    case .number(let value): return try canonicalNumber(value)
    case .string(let value): return canonicalString(value)
    case .array(let values):
        let rendered = try values.map { try canonicalJson($0) }.joined(separator: ",")
        return "[" + rendered + "]"
    case .object(let entries):
        let sorted = entries.sorted { compareUtf16($0.0, $1.0) }
        let rendered = try sorted.map { canonicalString($0.0) + ":" + (try canonicalJson($0.1)) }.joined(separator: ",")
        return "{" + rendered + "}"
    }
}

private func sha256(_ input: [UInt8]) -> [UInt8] {
    let roundConstants: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    let initialHash: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    var message = input
    let bitLength = UInt64(message.count) * 8
    message.append(0x80)
    while message.count % 64 != 56 { message.append(0) }
    for shift in stride(from: 56, through: 0, by: -8) { message.append(UInt8((bitLength >> UInt64(shift)) & 0xff)) }
    var hash = initialHash
    for offset in stride(from: 0, to: message.count, by: 64) {
        var words = Array(repeating: UInt32(0), count: 64)
        for i in 0..<16 {
            let p = offset + i * 4
            words[i] = (UInt32(message[p]) << 24) | (UInt32(message[p + 1]) << 16) | (UInt32(message[p + 2]) << 8) | UInt32(message[p + 3])
        }
        for i in 16..<64 {
            let s0 = words[i - 15].rotateRight(7) ^ words[i - 15].rotateRight(18) ^ (words[i - 15] >> 3)
            let s1 = words[i - 2].rotateRight(17) ^ words[i - 2].rotateRight(19) ^ (words[i - 2] >> 10)
            words[i] = words[i - 16] &+ s0 &+ words[i - 7] &+ s1
        }
        var a = hash[0], b = hash[1], c = hash[2], d = hash[3]
        var e = hash[4], f = hash[5], g = hash[6], h = hash[7]
        for i in 0..<64 {
            let s1 = e.rotateRight(6) ^ e.rotateRight(11) ^ e.rotateRight(25)
            let choice = (e & f) ^ ((~e) & g)
            let temp1 = h &+ s1 &+ choice &+ roundConstants[i] &+ words[i]
            let s0 = a.rotateRight(2) ^ a.rotateRight(13) ^ a.rotateRight(22)
            let majority = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ majority
            h = g; g = f; f = e; e = d &+ temp1; d = c; c = b; b = a; a = temp1 &+ temp2
        }
        hash[0] = hash[0] &+ a; hash[1] = hash[1] &+ b; hash[2] = hash[2] &+ c; hash[3] = hash[3] &+ d
        hash[4] = hash[4] &+ e; hash[5] = hash[5] &+ f; hash[6] = hash[6] &+ g; hash[7] = hash[7] &+ h
    }
    return hash.flatMap { value in (0..<4).map { UInt8((value >> UInt32(24 - $0 * 8)) & 0xff) } }
}

private extension UInt32 {
    func rotateRight(_ amount: UInt32) -> UInt32 { (self >> amount) | (self << (32 - amount)) }
}

private func sha256Hex(_ value: String) -> String {
    sha256(Array(value.utf8)).map { hex(UInt32($0), width: 2) }.joined()
}

private func readFile(path: String) throws -> [UInt8] {
    let descriptor = open(path, O_RDONLY)
    guard descriptor >= 0 else { throw ProbeError.invalidInput("vector file is unavailable") }
    defer { _ = close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0, info.st_size >= 0, info.st_size <= maximumInputBytes else {
        throw ProbeError.invalidInput("vector file is missing or oversized")
    }
    var output: [UInt8] = []
    var buffer = Array(repeating: UInt8(0), count: 16 * 1024)
    while true {
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        if count == 0 { break }
        guard count > 0 else { throw ProbeError.invalidInput("vector file read failed") }
        output.append(contentsOf: buffer[0..<count])
        guard Int64(output.count) <= maximumInputBytes else { throw ProbeError.invalidInput("vector file is oversized") }
    }
    return output
}

private func objectValue(_ entries: [(String, JSONValue)], _ key: String) -> JSONValue? {
    entries.first { $0.0 == key }?.1
}

private func stringValue(_ value: JSONValue?) -> String? {
    guard case .string(let value) = value else { return nil }
    return value
}

private func fail(_ message: String) -> Never {
    let output = Array(("canonical JSON probe: " + message + "\n").utf8)
    _ = output.withUnsafeBytes { Darwin.write(2, $0.baseAddress, $0.count) }
    exit(1)
}

private func run(path: String) throws {
    var parser = JSONParser(bytes: try readFile(path: path))
    guard case .object(let root) = try parser.parse() else { throw ProbeError.invalidInput("vector root is not an object") }
    let allowedRootKeys: Set<String> = ["profile", "encoding", "property_order", "number_format", "vectors"]
    guard Set(root.map(\.0)) == allowedRootKeys,
          stringValue(objectValue(root, "profile")) == "jcs-utf8-v1",
          stringValue(objectValue(root, "encoding")) == "UTF-8",
          stringValue(objectValue(root, "property_order")) == "UTF-16 code units",
          stringValue(objectValue(root, "number_format")) == "ECMAScript JSON.stringify",
          case .array(let vectors)? = objectValue(root, "vectors"),
          !vectors.isEmpty, vectors.count <= 64 else {
        throw ProbeError.invalidInput("vector metadata is malformed")
    }
    var passed = 0
    for rawVector in vectors {
        guard case .object(let vector) = rawVector,
              Set(vector.map(\.0)) == ["name", "value", "canonical", "sha256"],
              let name = stringValue(objectValue(vector, "name")), !name.isEmpty, name.count <= 128,
              let value = objectValue(vector, "value"),
              let expected = stringValue(objectValue(vector, "canonical")),
              let expectedDigest = stringValue(objectValue(vector, "sha256")),
              expectedDigest.count == 64,
              expectedDigest.allSatisfy({ ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") }) else {
            throw ProbeError.invalidInput("vector entry is malformed")
        }
        let actual = try canonicalJson(value)
        guard actual == expected else { throw ProbeError.invalidInput("vector \(name) canonical output mismatch") }
        guard sha256Hex(actual) == expectedDigest else { throw ProbeError.invalidInput("vector \(name) digest mismatch") }
        passed += 1
    }
    print("{\"profile\":\"jcs-utf8-v1\",\"vectors\":\(vectors.count),\"passed\":\(passed)}")
}

guard CommandLine.arguments.count == 2 else { fail("expected exactly one vector-file path") }
do {
    try run(path: CommandLine.arguments[1])
} catch ProbeError.invalidInput(let message) {
    fail(message)
} catch {
    fail("verification failed")
}

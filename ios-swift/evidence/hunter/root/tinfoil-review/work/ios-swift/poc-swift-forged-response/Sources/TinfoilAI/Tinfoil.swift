import Foundation
@_exported import OpenAI
import EHBP

/// Main entry point for the Tinfoil client library.
/// Provides the same API as OpenAI client with EHBP encryption for secure enclave communication.
public class TinfoilAI {
    private let openAIClient: OpenAI

    private init(client: OpenAI) {
        self.openAIClient = client
    }


    /// Internal initializer that sets up the EHBP session and OpenAI client.
    /// `userCacheSecret` is the already-resolved prompt-cache scoping secret
    /// (see `UserCacheSecret.resolve`).
    internal convenience init(
        apiKey: String?,
        apiKeyProvider: (@Sendable () -> String?)? = nil,
        baseURL: String,
        enclaveURL: String,
        hpkePublicKeyHex: String?,
        parsingOptions: ParsingOptions = .relaxed,
        customHeaders: [String: String] = [:],
        tinfoilEvents: Set<TinfoilEvent> = [],
        userCacheSecret: String = "",
        refreshEndpoint: EHBPVerifiedState.Refresh? = nil
    ) throws {
        guard let hpkeKeyHex = hpkePublicKeyHex, !hpkeKeyHex.isEmpty else {
            throw TinfoilError.invalidConfiguration("Server does not support EHBP (no HPKE public key)")
        }

        guard let hpkePublicKey = Data(hexString: hpkeKeyHex),
              hpkePublicKey.count == TinfoilConstants.hpkePublicKeyByteCount else {
            throw TinfoilError.invalidConfiguration("Invalid HPKE public key format (expected 32 bytes)")
        }

        let urlComponents = try URLHelpers.parseHTTPURL(baseURL)

        let verifiedState = EHBPVerifiedState(
            endpoint: EHBPVerifiedEndpoint(
                enclaveURL: enclaveURL,
                publicKey: hpkePublicKey
            ),
            refresh: refreshEndpoint
        )

        let ehbpSession = EHBPURLSession(
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret
        )

        let ehbpStreamingFactory = EHBPURLSessionFactory(
            baseURL: baseURL,
            verifiedState: verifiedState,
            userCacheSecret: userCacheSecret
        )

        let defaultPort = urlComponents.scheme == "https" ? 443 : 80

        var mergedHeaders = customHeaders
        if let eventsHeader = tinfoilEventsHeaderValue(tinfoilEvents),
           !mergedHeaders.keys.contains(where: { $0.caseInsensitiveCompare(tinfoilEventsHeader) == .orderedSame }) {
            mergedHeaders[tinfoilEventsHeader] = eventsHeader
        }

        let configuration = OpenAI.Configuration(
            token: apiKey,
            tokenProvider: apiKeyProvider,
            host: urlComponents.host,
            port: urlComponents.port ?? defaultPort,
            scheme: urlComponents.scheme,
            customHeaders: mergedHeaders,
            parsingOptions: parsingOptions
        )

        let openAIClient = OpenAI(
            configuration: configuration,
            customSession: ehbpSession,
            streamingURLSessionFactory: ehbpStreamingFactory
        )

        self.init(client: openAIClient)
    }

    // MARK: - OpenAI API Forwarding (Async)

    public func chats(query: ChatQuery) async throws -> ChatResult {
        try await openAIClient.chats(query: query)
    }

    /// Sends a chat completion with additional headers applied to this call
    /// only, on top of the client's `customHeaders`. Use this for values that
    /// change per request, such as a conversation id.
    public func chats(query: ChatQuery, headers: [String: String]) async throws -> ChatResult {
        try await openAIClient.chats(query: query, headers: headers)
    }

    public func chatsStream(query: ChatQuery) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAIClient.chatsStream(query: query)
    }

    /// Streams a chat completion with additional headers applied to this call
    /// only, on top of the client's `customHeaders`. Use this for values that
    /// change per request, such as a conversation id.
    public func chatsStream(query: ChatQuery, headers: [String: String]) -> AsyncThrowingStream<ChatStreamResult, Error> {
        openAIClient.chatsStream(query: query, headers: headers)
    }

    public func images(query: ImagesQuery) async throws -> ImagesResult {
        try await openAIClient.images(query: query)
    }

    public func imageEdits(query: ImageEditsQuery) async throws -> ImagesResult {
        try await openAIClient.imageEdits(query: query)
    }

    public func imageVariations(query: ImageVariationsQuery) async throws -> ImagesResult {
        try await openAIClient.imageVariations(query: query)
    }

    public func embeddings(query: EmbeddingsQuery) async throws -> EmbeddingsResult {
        try await openAIClient.embeddings(query: query)
    }

    public func model(query: ModelQuery) async throws -> ModelResult {
        try await openAIClient.model(query: query)
    }

    public func models() async throws -> ModelsResult {
        try await openAIClient.models()
    }

    public func moderations(query: ModerationsQuery) async throws -> ModerationsResult {
        try await openAIClient.moderations(query: query)
    }

    public func audioCreateSpeech(query: AudioSpeechQuery) async throws -> AudioSpeechResult {
        try await openAIClient.audioCreateSpeech(query: query)
    }

    public func audioCreateSpeechStream(query: AudioSpeechQuery) -> AsyncThrowingStream<AudioSpeechResult, Error> {
        openAIClient.audioCreateSpeechStream(query: query)
    }

    /// Streams EHBP-encrypted speech with response validation options, such as
    /// requiring `audio/pcm` before delivering bytes to a PCM player.
    public func audioCreateSpeechStream(query: AudioSpeechQuery, options: AudioSpeechStreamOptions) -> AsyncThrowingStream<AudioSpeechResult, Error> {
        openAIClient.audioCreateSpeechStream(query: query, options: options)
    }

    public func audioTranscriptions(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionResult {
        try await openAIClient.audioTranscriptions(query: query)
    }

    public func audioTranscriptionsVerbose(query: AudioTranscriptionQuery) async throws -> AudioTranscriptionVerboseResult {
        try await openAIClient.audioTranscriptionsVerbose(query: query)
    }

    public func audioTranscriptionStream(query: AudioTranscriptionQuery) -> AsyncThrowingStream<AudioTranscriptionStreamResult, Error> {
        openAIClient.audioTranscriptionStream(query: query)
    }

    public func audioTranslations(query: AudioTranslationQuery) async throws -> AudioTranslationResult {
        try await openAIClient.audioTranslations(query: query)
    }

    public func assistants() async throws -> AssistantsResult {
        try await openAIClient.assistants()
    }

    public func assistants(after: String?) async throws -> AssistantsResult {
        try await openAIClient.assistants(after: after)
    }

    public func assistantCreate(query: AssistantsQuery) async throws -> AssistantResult {
        try await openAIClient.assistantCreate(query: query)
    }

    public func assistantModify(query: AssistantsQuery, assistantId: String) async throws -> AssistantResult {
        try await openAIClient.assistantModify(query: query, assistantId: assistantId)
    }

    public func threads(query: ThreadsQuery) async throws -> ThreadsResult {
        try await openAIClient.threads(query: query)
    }

    public func threadRun(query: ThreadRunQuery) async throws -> RunResult {
        try await openAIClient.threadRun(query: query)
    }

    public func runs(threadId: String, query: RunsQuery) async throws -> RunResult {
        try await openAIClient.runs(threadId: threadId, query: query)
    }

    public func runRetrieve(threadId: String, runId: String) async throws -> RunResult {
        try await openAIClient.runRetrieve(threadId: threadId, runId: runId)
    }

    public func runRetrieveSteps(threadId: String, runId: String) async throws -> RunRetrieveStepsResult {
        try await openAIClient.runRetrieveSteps(threadId: threadId, runId: runId)
    }

    public func runRetrieveSteps(threadId: String, runId: String, before: String?) async throws -> RunRetrieveStepsResult {
        try await openAIClient.runRetrieveSteps(threadId: threadId, runId: runId, before: before)
    }

    public func runSubmitToolOutputs(threadId: String, runId: String, query: RunToolOutputsQuery) async throws -> RunResult {
        try await openAIClient.runSubmitToolOutputs(threadId: threadId, runId: runId, query: query)
    }

    public func threadsMessages(threadId: String) async throws -> ThreadsMessagesResult {
        try await openAIClient.threadsMessages(threadId: threadId)
    }

    public func threadsMessages(threadId: String, before: String?) async throws -> ThreadsMessagesResult {
        try await openAIClient.threadsMessages(threadId: threadId, before: before)
    }

    public func threadsAddMessage(threadId: String, query: MessageQuery) async throws -> ThreadAddMessageResult {
        try await openAIClient.threadsAddMessage(threadId: threadId, query: query)
    }

    public func files(query: FilesQuery) async throws -> FilesResult {
        try await openAIClient.files(query: query)
    }

    // MARK: - Responses API

    public func createResponse(query: CreateModelResponseQuery) async throws -> ResponseObject {
        try await openAIClient.responses.createResponse(query: query)
    }

    public func createResponseStream(query: CreateModelResponseQuery) -> AsyncThrowingStream<ResponseStreamEvent, Error> {
        openAIClient.responses.createResponseStreaming(query: query)
    }
}

/// Errors that can occur when using the Tinfoil client
public enum TinfoilError: Error, Equatable {
    case missingAPIKey
    case invalidConfiguration(String)
    case connectionError(String)
}

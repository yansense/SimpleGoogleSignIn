import Foundation
import UIKit
import AuthenticationServices
import CryptoKit

// MARK: - Error Types

enum GoogleSignInError: LocalizedError {
    case missingConfiguration
    case missingPresentingViewController
    case authenticationFailed(String)
    case invalidResponse
    case userCancelled
    case networkError(Error)
    case missingURLScheme(String)
    
    var errorDescription: String? {
        switch self {
        case .missingConfiguration:
            return "Google Sign-In configuration is missing"
        case .missingPresentingViewController:
            return "No presenting view controller available"
        case .authenticationFailed(let message):
            return "Authentication failed: \(message)"
        case .invalidResponse:
            return "Invalid response from Google"
        case .userCancelled:
            return "User cancelled sign-in"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .missingURLScheme(let scheme):
            return "Required URL scheme '\(scheme)' is not configured in Info.plist"
        }
    }
}

// MARK: - Configuration

public struct GoogleSignInConfiguration {
    let clientID: String
    let serverClientID: String?
    let hostedDomain: String?
    
    public init(
        clientID: String,
        serverClientID: String? = nil,
        hostedDomain: String? = nil
    ) {
        self.clientID = clientID
        self.serverClientID = serverClientID
        self.hostedDomain = hostedDomain
    }
}

// MARK: - Token

public struct GoogleToken {
    public let tokenString: String
    public let expirationDate: Date?
    
    public var isExpired: Bool {
        guard let expirationDate = expirationDate else { return false }
        return expirationDate <= Date()
    }
}

// MARK: - Sign In Result

public struct GoogleSignInResult {
    public let openIdToken: String?
    public let accessToken: GoogleToken
    public let refreshToken: String?
    public let grantedScopes: [String]?
    public let nonce: String?
}

// MARK: - Main Sign In Class

public class SimpleGoogleSignIn: NSObject {
    
    // MARK: - Singleton
    
    public static let shared = SimpleGoogleSignIn()
    
    // MARK: - Properties
    
    public var configuration: GoogleSignInConfiguration?
    
    private var authSession: ASWebAuthenticationSession?
    private var signInCompletion: ((Result<GoogleSignInResult, Error>) -> Void)?
    private weak var presentingViewController: UIViewController?
    
    // MARK: - Initialization
    
    private override init() {
        super.init()
    }
    
    // MARK: - Public Methods
    
    public func configure(configuration: GoogleSignInConfiguration) {
        self.configuration = configuration
    }
    
    public func signIn(
        presentingViewController: UIViewController,
        hint: String? = nil,
        nonce: String? = nil,
        scopes: [String],
        completion: @escaping (Result<GoogleSignInResult, Error>) -> Void
    ) {
        guard let configuration = configuration else {
            completion(.failure(GoogleSignInError.missingConfiguration))
            return
        }
        
        if !hasSupportedURLSchemes() {
            completion(.failure(GoogleSignInError.missingURLScheme(getCallbackScheme())))
            return
        }
        
        self.signInCompletion = completion
        self.presentingViewController = presentingViewController
        
        // Generate PKCE parameters
        let codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(from: codeVerifier)
        let state = UUID().uuidString
        let usedNonce = nonce ?? UUID().uuidString
        
        // Build authorization URL
        var components = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: getRedirectURI()),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: usedNonce),
            URLQueryItem(name: "include_granted_scopes", value: "true"),
            URLQueryItem(name: "access_type", value: "offline")
        ]
        
        if let hint = hint {
            components.queryItems?.append(URLQueryItem(name: "login_hint", value: hint))
        }
        
        if let hostedDomain = configuration.hostedDomain {
            components.queryItems?.append(URLQueryItem(name: "hd", value: hostedDomain))
        }
        
        guard let authURL = components.url else {
            completion(.failure(GoogleSignInError.invalidResponse))
            return
        }
        
        // Create and start authentication session
        let session = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: getCallbackScheme()
        ) { [weak self] callbackURL, error in
            self?.handleAuthenticationCallback(
                callbackURL: callbackURL,
                error: error,
                codeVerifier: codeVerifier,
                expectedState: state,
                expectedNonce: usedNonce
            )
        }
        
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        
        authSession = session
        session.start()
    }
    
    public func signOut(accessToken: String?, completion: @escaping (Error?) -> Void) {
        guard let token = accessToken else {
            cleanup()
            completion(nil)
            return
        }
        
        GoogleAuthService.revokeToken(token) { [weak self] error in
            self?.cleanup()
            DispatchQueue.main.async {
                completion(error)
            }
        }
    }

    public func refreshTokens(refreshToken: String, completion: @escaping (Result<GoogleSignInResult, Error>) -> Void) {
        guard let configuration = configuration else {
            completion(.failure(GoogleSignInError.missingConfiguration))
            return
        }
        
        GoogleAuthService.refreshTokens(
            refreshToken: refreshToken,
            clientID: configuration.clientID
        ) { [weak self] result in
            switch result {
            case .success(let response):
                let updatedUser = GoogleSignInResult(
                    openIdToken: response.openIdToken?.tokenString ?? "",
                    accessToken: response.accessToken,
                    refreshToken: response.refreshToken ?? refreshToken,
                    grantedScopes: response.scope?.components(separatedBy: " ") ?? [],
                    nonce: nil  // refresh token 不需要 nonce
                )

                DispatchQueue.main.async {
                    completion(.success(updatedUser))
                }
                
            case .failure(let error):
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
    }    
    
    public func handleURL(_ url: URL) -> Bool {
        guard url.scheme == getCallbackScheme() else { return false }
        // The ASWebAuthenticationSession will handle this automatically
        return true
    }
    
    // MARK: - Internal Methods
    
    private func cleanup() {
        authSession?.cancel()
        authSession = nil
        presentingViewController = nil
    }
    
    private func hasSupportedURLSchemes() -> Bool {
        guard let configuration = configuration else { return false }
        let requiredScheme = getCallbackScheme().lowercased()
        
        guard let urlTypes = Bundle.main.infoDictionary?["CFBundleURLTypes"] as? [[String: Any]] else {
            return false
        }
        
        for urlType in urlTypes {
            if let urlSchemes = urlType["CFBundleURLSchemes"] as? [String] {
                for scheme in urlSchemes {
                    if scheme.lowercased() == requiredScheme {
                        return true
                    }
                }
            }
        }
        return false
    }

    private func getRedirectURI() -> String {
        return "\(getCallbackScheme()):/oauth2callback"
    }
    
    private func getCallbackScheme() -> String {
        guard let configuration = configuration else {
            fatalError("Google Sign-In configuration is required")
        }
        // Extract the client ID part before ".apps.googleusercontent.com"
        let clientID = configuration.clientID
        guard clientID.hasSuffix(".apps.googleusercontent.com") else {
            fatalError("Invalid client ID format. Expected format: YOUR_CLIENT_ID.apps.googleusercontent.com")
        }
        
        let clientIDPrefix = clientID.replacingOccurrences(of: ".apps.googleusercontent.com", with: "")
        // Reversed client ID format: com.googleusercontent.apps.YOUR_CLIENT_ID
        return "com.googleusercontent.apps.\(clientIDPrefix)"
    }
    
    private func handleAuthenticationCallback(
        callbackURL: URL?,
        error: Error?,
        codeVerifier: String,
        expectedState: String,
        expectedNonce: String
    ) {
        defer {
            authSession = nil
        }
        
        if let error = error {
            if (error as NSError).code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                signInCompletion?(.failure(GoogleSignInError.userCancelled))
            } else {
                signInCompletion?(.failure(error))
            }
            signInCompletion = nil
            return
        }
        
        guard let callbackURL = callbackURL,
              let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            signInCompletion?(.failure(GoogleSignInError.invalidResponse))
            signInCompletion = nil
            return
        }
        
        let params: [String: String] = Dictionary(uniqueKeysWithValues: queryItems.compactMap { item in
            guard let value = item.value else { return nil }
            return (item.name, value)
        })
        
        // Check for error
        if let error = params["error"] {
            let description = params["error_description"] ?? error
            signInCompletion?(.failure(GoogleSignInError.authenticationFailed(description)))
            signInCompletion = nil
            return
        }
        
        // Verify state
        guard params["state"] == expectedState else {
            signInCompletion?(.failure(GoogleSignInError.authenticationFailed("State mismatch")))
            signInCompletion = nil
            return
        }
        
        // Get authorization code
        guard let code = params["code"] else {
            signInCompletion?(.failure(GoogleSignInError.invalidResponse))
            signInCompletion = nil
            return
        }
        
        // Exchange code for tokens
        exchangeCodeForTokens(
            code: code,
            codeVerifier: codeVerifier,
            expectedNonce: expectedNonce
        )
    }
    
    private func exchangeCodeForTokens(
        code: String,
        codeVerifier: String,
        expectedNonce: String
    ) {
        guard let configuration = configuration else {
            signInCompletion?(.failure(GoogleSignInError.missingConfiguration))
            signInCompletion = nil
            return
        }
        
        GoogleAuthService.exchangeCodeForTokens(
            code: code,
            codeVerifier: codeVerifier,
            clientID: configuration.clientID,
            redirectURI: getRedirectURI()
        ) { [weak self] result in
            switch result {
            case .success(let response):
                self?.handleTokenResponse(response, expectedNonce: expectedNonce)
                
            case .failure(let error):
                DispatchQueue.main.async {
                    self?.signInCompletion?(.failure(error))
                    self?.signInCompletion = nil
                }
            }
        }
    }
    
    private func handleTokenResponse(_ response: TokenResponse, expectedNonce: String) {
        let result = GoogleSignInResult(
            openIdToken: response.openIdToken?.tokenString ?? "",
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            grantedScopes: response.scope?.components(separatedBy: " ") ?? [],
            nonce: expectedNonce
        )
        
        DispatchQueue.main.async { [weak self] in
            self?.signInCompletion?(.success(result))
            self?.signInCompletion = nil
        }
    }
    
    // MARK: - PKCE Helpers
    
    private func generateCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return Data(buffer).base64URLEncodedString()
    }
    
    private func generateCodeChallenge(from verifier: String) -> String {
        let data = verifier.data(using: .utf8)!
        let hash = SHA256.hash(data: data)
        return Data(hash).base64URLEncodedString()
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension SimpleGoogleSignIn: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let window = presentingViewController?.view.window else {
            // Fallback to key window if presenting view controller's window is not available
            return UIApplication.shared.windows.first { $0.isKeyWindow } ?? UIWindow()
        }
        return window
    }
}

// MARK: - Network Service

private struct TokenResponse {
    let accessToken: GoogleToken
    let openIdToken: GoogleToken?
    let refreshToken: String?
    let scope: String?
}

private class GoogleAuthService {
    
    static func exchangeCodeForTokens(
        code: String,
        codeVerifier: String,
        clientID: String,
        redirectURI: String,
        completion: @escaping (Result<TokenResponse, Error>) -> Void
    ) {
        let url = URL(string: "https://oauth2.googleapis.com/token")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let params = [
            "code": code,
            "client_id": clientID,
            "code_verifier": codeVerifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirectURI
        ]
        
        request.httpBody = params
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(GoogleSignInError.networkError(error)))
                return
            }
            
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(GoogleSignInError.invalidResponse))
                return
            }
            
            guard let accessTokenString = json["access_token"] as? String else {
                let errorMessage = json["error_description"] as? String ?? "Unknown error"
                completion(.failure(GoogleSignInError.authenticationFailed(errorMessage)))
                return
            }
            
            let expiresIn = json["expires_in"] as? TimeInterval ?? 3600
            let accessToken = GoogleToken(
                tokenString: accessTokenString,
                expirationDate: Date().addingTimeInterval(expiresIn)
            )
            
            var openIdToken: GoogleToken?
            if let idTokenString = json["id_token"] as? String {
                openIdToken = GoogleToken(tokenString: idTokenString, expirationDate: nil)
            }
            
            let response = TokenResponse(
                accessToken: accessToken,
                openIdToken: openIdToken,
                refreshToken: json["refresh_token"] as? String,
                scope: json["scope"] as? String
            )
            
            completion(.success(response))
            
        }.resume()
    }
    
    static func refreshTokens(
        refreshToken: String,
        clientID: String,
        completion: @escaping (Result<TokenResponse, Error>) -> Void
    ) {
        let url = URL(string: "https://oauth2.googleapis.com/token")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let params = [
            "refresh_token": refreshToken,
            "client_id": clientID,
            "grant_type": "refresh_token"
        ]
        
        request.httpBody = params
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(GoogleSignInError.networkError(error)))
                return
            }
            
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(GoogleSignInError.invalidResponse))
                return
            }
            
            guard let accessTokenString = json["access_token"] as? String else {
                let errorMessage = json["error_description"] as? String ?? "Unknown error"
                completion(.failure(GoogleSignInError.authenticationFailed(errorMessage)))
                return
            }
            
            let expiresIn = json["expires_in"] as? TimeInterval ?? 3600
            let accessToken = GoogleToken(
                tokenString: accessTokenString,
                expirationDate: Date().addingTimeInterval(expiresIn)
            )
            
            var openIdToken: GoogleToken?
            if let idTokenString = json["id_token"] as? String {
                openIdToken = GoogleToken(tokenString: idTokenString, expirationDate: nil)
            }
            
            let response = TokenResponse(
                accessToken: accessToken,
                openIdToken: openIdToken,
                refreshToken: json["refresh_token"] as? String,
                scope: json["scope"] as? String
            )
            
            completion(.success(response))
            
        }.resume()
    }
    
    static func revokeToken(_ token: String, completion: @escaping (Error?) -> Void) {
        let url = URL(string: "https://oauth2.googleapis.com/revoke")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "token=\(token)".data(using: .utf8)
        
        URLSession.shared.dataTask(with: request) { _, _, error in
            completion(error)
        }.resume()
    }
}

// MARK: - Data Extensions

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

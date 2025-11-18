import Foundation
import Capacitor

/**
 * @file SSLCertificateCheckerPlugin.swift
 * This file defines the implementation of the Capacitor plugin `SSLCertificateCheckerPlugin` for iOS.
 * The plugin provides an interface between JavaScript and native iOS code, allowing Capacitor applications
 * to interact with SSL certificate verification functionality.
 *
 * Documentation Reference: https://capacitorjs.com/docs/plugins/ios
 */

@objc(SSLCertificateCheckerPlugin)
/**
 * The `SSLCertificateCheckerPlugin` class acts as the main entry point for the Capacitor plugin on the iOS platform.
 * It extends `CAPPlugin` and conforms to the `CAPBridgedPlugin` protocol.
 * This plugin enables JavaScript code to perform SSL certificate validation through native iOS functionality.
 */
public class SSLCertificateCheckerPlugin: CAPPlugin, CAPBridgedPlugin {

    /**
     * Called when the plugin is loaded.
     * Override this method to perform any initial setup or configuration for the plugin when it is first loaded.
     */
    override public func load() {
        log("Loading plugin")
    }

    /// The unique identifier for the plugin, used by Capacitor's internal mechanisms.
    public let identifier = "SSLCertificateCheckerPlugin"

    /// The JavaScript name used to reference this plugin in Capacitor applications.
    public let jsName = "SSLCertificateChecker"

    /**
     * A list of methods exposed by this plugin.
     * These methods can be called from the JavaScript side of the application.
     */
    public let pluginMethods: [CAPPluginMethod] = [
        /**
         * `checkCertificate`:
         * A method that validates the SSL certificate of a given URL against a provided fingerprint.
         * Returns a promise to the JavaScript caller with the result of the validation.
         */
        CAPPluginMethod(name: "checkCertificate", returnType: CAPPluginReturnPromise)
    ]

    /// An instance of the implementation class that contains the plugin's core functionality.
    private let implementation = SSLCertificateChecker()

    /**
     * This method validates an SSL certificate for a given URL against an expected fingerprint.
     *
     * - Parameters:
     *   - call: An instance of `CAPPluginCall` containing the method call information from JavaScript.
     *           The call must include the following properties:
     *           - `url`: The URL of the server whose SSL certificate is to be validated.
     *           - `fingerprint`: The expected fingerprint of the SSL certificate.
     *
     * - Note:
     *   If either the `url` or `fingerprint` is missing, the call will be rejected with an error message.
     *   The `implementation.checkCertificate` method is invoked to perform the actual validation.
     *
     * - Returns:
     *   Resolves the call with the result of the certificate validation if successful.
     *   Rejects the call with an error if input parameters are invalid or validation fails.
     */
    @objc func checkCertificate(_ call: CAPPluginCall) {
        // Retrieve the `url` and `fingerprint` parameters from the method call.
        guard let url = call.getString("url") else {
            call.reject("Must provide url")
            return
        }

        let singleFingerprint = call.getString("fingerprint")
        let multipleFingerprints = call.getArray("fingerprints", String.self)

        if singleFingerprint == nil && (multipleFingerprints == nil || multipleFingerprints?.isEmpty == true) {
            call.reject("Must provide either 'fingerprint' (string) or 'fingerprints' (array of strings)")
            return
        }

        // Prioritize 'fingerprints' array if both are provided
        let result: [String: Any]
        if let fingerprints = multipleFingerprints, !fingerprints.isEmpty {
            result = implementation.checkCertificate(url, expectedFingerprints: fingerprints)
        } else if let fingerprint = singleFingerprint {
            result = implementation.checkCertificate(url, expectedFingerprint: fingerprint)
        } else {
            call.reject("Invalid fingerprint parameter(s) provided")
            return
        }

        // Resolve the call with the validation result.
        call.resolve(result)
    }
}

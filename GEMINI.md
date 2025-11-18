# Gemini Code Understanding

## Project Overview

This project is a Capacitor plugin for SSL certificate pinning. It allows a mobile application to verify the SSL certificate of a server it connects to, in order to prevent man-in-the-middle attacks.

The plugin provides a `checkCertificate` method that takes a URL and an expected SHA256 fingerprint as input. It then connects to the server, retrieves the server's SSL certificate, calculates its SHA256 fingerprint, and compares it to the expected fingerprint.

The project includes:

-   A core plugin that is registered with Capacitor.
-   Native implementations for iOS and Android.
-   A web implementation that throws an "unimplemented" error, as this functionality is not available in browsers.
-   A command-line interface (CLI) tool to fetch the SSL certificate for a domain and display its fingerprint.

## Building and Running

### Building the project

To build the project, run the following command:

```bash
npm run build
```

This command will compile the TypeScript code and bundle it into a distributable format.

### Running the tests

To run the tests, run the following command:

```bash
npm run verify
```

This command will run the tests for iOS, Android, and web.

### Using the CLI tool

The project includes a CLI tool to fetch the SSL certificate for a domain and display its fingerprint. To use the CLI tool, run the following command:

```bash
npx ssl-fingerprint <domain>
```

Replace `<domain>` with the domain you want to check.

## Development Conventions

### Coding Style

The project uses ESLint and Prettier for code formatting and style checking. To check the code for style and errors, run the following command:

```bash
npm run lint
```

To automatically fix any style issues, run the following command:

```bash
npm run fmt
```

### Testing

The project uses a combination of unit tests and integration tests to ensure the quality of the code. The tests are located in the `tests` directory for each platform (iOS and Android).

### Contribution Guidelines

The project has a `CONTRIBUTING.md` file that outlines the contribution guidelines. It is recommended to read this file before contributing to the project.

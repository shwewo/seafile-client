#ifndef SEAFILE_CLIENT_UTILS_MTLS_H
#define SEAFILE_CLIENT_UTILS_MTLS_H

#include <QString>

/*
 * Mutual TLS (client certificate) helpers.
 *
 * Client certificates are configured per server host (each account may use a
 * different certificate). The registry below is populated from saved accounts
 * and from the login dialog before authentication.
 *
 * As a host-agnostic fallback, a single certificate may also be supplied via
 * environment variables (handy for headless/test setups):
 *
 *   SEAFILE_CLIENT_SSL_CERT_PATH      PEM cert or .p12 bundle
 *   SEAFILE_CLIENT_SSL_KEY_PATH       PEM private key (PEM only)
 *   SEAFILE_CLIENT_SSL_CERT_TYPE      "PEM" (default) or "P12"
 *   SEAFILE_CLIENT_SSL_CERT_PASSWORD  key / bundle passphrase
 */

class QUrl;
class QSslConfiguration;
class QSslCertificate;
class QSslKey;

namespace mtls {

struct CertConfig {
    QString certPath;
    QString keyPath;
    QString certType;   // "PEM" (default) or "P12"
    QString password;

    bool isEmpty() const { return certPath.isEmpty(); }
};

// Register (or replace) the client certificate presented to a server host.
// An empty certPath removes any registration for that host.
void setHostCert(const QString& host, const CertConfig& cfg);
void removeHostCert(const QString& host);

// Retrieve the certificate explicitly registered for a host (not the env
// fallback). Returns false if none is registered.
bool hostCert(const QString& host, CertConfig* out);

// True if a client certificate is configured for this url's host (or via the
// environment fallback).
bool hasCertForUrl(const QUrl& url);

// Build the QSslConfiguration carrying the client certificate for this url's
// host. Returns false (leaving *out untouched) when none is configured or it
// could not be loaded.
bool configurationForUrl(const QUrl& url, QSslConfiguration* out);

// Load just the certificate and private key for this url's host, e.g. to feed
// QtWebEngine's client certificate store for SSO. Returns false on failure.
bool certAndKeyForUrl(const QUrl& url, QSslCertificate* cert, QSslKey* key);

} // namespace mtls

#endif // SEAFILE_CLIENT_UTILS_MTLS_H

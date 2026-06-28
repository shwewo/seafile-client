#include <QByteArray>
#include <QFile>
#include <QHash>
#include <QList>
#include <QSettings>
#include <QString>
#include <QUrl>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>

#include "mtls.h"

namespace {

// host (lowercased) -> certificate configuration
QHash<QString, mtls::CertConfig> g_host_certs;
// host -> built QSslConfiguration cache (empty config means "not loadable")
QHash<QString, QSslConfiguration> g_config_cache;

QString hostKey(const QString& host)
{
    return host.toLower();
}

// Host-agnostic fallback from environment variables (and, for backwards
// compatibility, the old global QSettings keys).
mtls::CertConfig envFallback()
{
    mtls::CertConfig cfg;

    QByteArray p = qgetenv("SEAFILE_CLIENT_SSL_CERT_PATH");
    if (!p.isEmpty()) {
        cfg.certPath = QString::fromUtf8(p);
        cfg.keyPath = QString::fromUtf8(qgetenv("SEAFILE_CLIENT_SSL_KEY_PATH"));
        cfg.certType = QString::fromUtf8(qgetenv("SEAFILE_CLIENT_SSL_CERT_TYPE"));
        cfg.password = QString::fromUtf8(qgetenv("SEAFILE_CLIENT_SSL_CERT_PASSWORD"));
        return cfg;
    }

    QSettings settings;
    settings.beginGroup("Settings");
    cfg.certPath = settings.value("clientSslCertPath").toString();
    cfg.keyPath = settings.value("clientSslKeyPath").toString();
    cfg.certType = settings.value("clientSslCertType").toString();
    cfg.password = settings.value("clientSslCertPassword").toString();
    settings.endGroup();
    return cfg;
}

mtls::CertConfig resolveConfig(const QString& host)
{
    QString key = hostKey(host);
    if (g_host_certs.contains(key)) {
        return g_host_certs.value(key);
    }
    return envFallback();
}

// QSslKey requires the algorithm to be specified up front, so try each one.
QSslKey loadPrivateKey(const QByteArray& pem, const QByteArray& passphrase)
{
    const QSsl::KeyAlgorithm algos[] = {QSsl::Rsa, QSsl::Ec, QSsl::Dsa};
    for (size_t i = 0; i < sizeof(algos) / sizeof(algos[0]); ++i) {
        QSslKey key(pem, algos[i], QSsl::Pem, QSsl::PrivateKey, passphrase);
        if (!key.isNull()) {
            return key;
        }
    }
    return QSslKey();
}

bool loadCertKey(const mtls::CertConfig& cfg,
                 QSslCertificate* cert_out, QSslKey* key_out)
{
    if (cfg.isEmpty()) {
        return false;
    }

    QByteArray password = cfg.password.toUtf8();

    QFile cert_file(cfg.certPath);
    if (!cert_file.open(QIODevice::ReadOnly)) {
        qWarning("[mtls] cannot open client certificate %s",
                 cfg.certPath.toUtf8().constData());
        return false;
    }

    if (cfg.certType.compare("P12", Qt::CaseInsensitive) == 0) {
        QSslKey key;
        QSslCertificate cert;
        QList<QSslCertificate> ca_certs;
        if (!QSslCertificate::importPkcs12(&cert_file, &key, &cert, &ca_certs,
                                           password)) {
            qWarning("[mtls] failed to import PKCS#12 bundle %s (wrong password?)",
                     cfg.certPath.toUtf8().constData());
            return false;
        }
        *cert_out = cert;
        *key_out = key;
        return !cert.isNull() && !key.isNull();
    }

    // PEM certificate + private key.
    QList<QSslCertificate> certs =
        QSslCertificate::fromData(cert_file.readAll(), QSsl::Pem);
    if (certs.isEmpty()) {
        qWarning("[mtls] no PEM certificate found in %s",
                 cfg.certPath.toUtf8().constData());
        return false;
    }

    QByteArray key_pem;
    if (!cfg.keyPath.isEmpty()) {
        QFile key_file(cfg.keyPath);
        if (key_file.open(QIODevice::ReadOnly)) {
            key_pem = key_file.readAll();
        }
    } else {
        // The key may live in the same PEM file as the certificate.
        cert_file.seek(0);
        key_pem = cert_file.readAll();
    }

    QSslKey key = loadPrivateKey(key_pem, password);
    if (key.isNull()) {
        qWarning("[mtls] failed to load PEM private key for %s",
                 cfg.certPath.toUtf8().constData());
        return false;
    }

    *cert_out = certs.first();
    *key_out = key;
    return true;
}

} // namespace

namespace mtls {

void setHostCert(const QString& host, const CertConfig& cfg)
{
    QString key = hostKey(host);
    g_config_cache.remove(key);
    if (cfg.isEmpty()) {
        g_host_certs.remove(key);
        return;
    }
    g_host_certs.insert(key, cfg);
}

void removeHostCert(const QString& host)
{
    QString key = hostKey(host);
    g_host_certs.remove(key);
    g_config_cache.remove(key);
}

bool hostCert(const QString& host, CertConfig* out)
{
    QString key = hostKey(host);
    if (!g_host_certs.contains(key)) {
        return false;
    }
    *out = g_host_certs.value(key);
    return true;
}

bool hasCertForUrl(const QUrl& url)
{
    return !resolveConfig(url.host()).isEmpty();
}

bool configurationForUrl(const QUrl& url, QSslConfiguration* out)
{
    QString key = hostKey(url.host());

    if (g_config_cache.contains(key)) {
        QSslConfiguration cached = g_config_cache.value(key);
        if (cached.isNull()) {
            return false;   // previously determined not loadable
        }
        *out = cached;
        return true;
    }

    QSslCertificate cert;
    QSslKey pkey;
    if (!loadCertKey(resolveConfig(url.host()), &cert, &pkey)) {
        // Cache the negative result to avoid re-reading files every request.
        g_config_cache.insert(key, QSslConfiguration());
        return false;
    }

    QSslConfiguration config = QSslConfiguration::defaultConfiguration();
    config.setLocalCertificate(cert);
    config.setPrivateKey(pkey);
    g_config_cache.insert(key, config);
    *out = config;
    return true;
}

bool certAndKeyForUrl(const QUrl& url, QSslCertificate* cert, QSslKey* key)
{
    return loadCertKey(resolveConfig(url.host()), cert, key);
}

} // namespace mtls

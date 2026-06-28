#ifndef SEAFILE_CLIENT_LOGIN_DIALOG_H
#define SEAFILE_CLIENT_LOGIN_DIALOG_H

#include <QDialog>
#include "ui_login-dialog.h"

#include <QUrl>
#include <QTimer>
#include <QString>
#include <QNetworkReply>
#include <QSslError>

#include "two-factor-dialog.h"

class Account;
class LoginRequest;
class QNetworkReply;
class ApiError;
class FetchAccountInfoRequest;
class AccountInfo;
class ServerInfo;
class ClientSSOStatus;
class QCheckBox;
class QLineEdit;
class QLabel;
class QWidget;

class LoginDialog : public QDialog,
                    public Ui::LoginDialog
{
    Q_OBJECT
public:
    LoginDialog(QWidget *parent=0);
    void initFromAccount(const Account& account);

private slots:
    void doLogin();
    void loginSuccess(const QString& token, const QString& s2fa_token);
    void loginFailed(const ApiError& error);
    void onFetchAccountInfoSuccess(const AccountInfo& info);
    void onFetchAccountInfoFailed(const ApiError&);
    void browseClientCert();
    void browseClientKey();
#ifdef HAVE_CLIENT_SSO_SUPPORT
    void loginWithShib();
    void serverInfoSuccess(const ServerInfo&);
    void serverInfoFailed(const ApiError&);
    void clientSSOLinkSuccess(const QString&);
    void clientSSOLinkFailed(const ApiError&);
    void checkClientSSOStatus();
    void clientSSOStatusSuccess(const ClientSSOStatus&);
    void clientSSOStatusFailed(const ApiError&);
#endif // HAVE_CLIENT_SSO_SUPPORT

private:
    Q_DISABLE_COPY(LoginDialog);

    enum LoginMode {
        LOGIN_NORMAL = 0,
        LOGIN_SHIB
    };

    void setupShibLoginLink();
    bool validateInputs();
    void disableInputs();
    void enableInputs();
    void showWarning(const QString& msg);

    // Mutual TLS (client certificate) section.
    void setupMtlsSection();
    // Register the entered certificate for the given server host so the login
    // and account-info requests present it.
    void applyMtlsForLogin(const QUrl& server_url);
    // "P12" if the selected certificate is a PKCS#12 bundle, else "PEM".
    QString detectedCertType() const;
    // Show the private-key picker only for PEM certificates.
    void updateMtlsKeyRow();

    void onNetworkError(const QNetworkReply::NetworkError& error, const QString& error_string);
    void onSslErrors(QNetworkReply *reply, const QList<QSslError>& errors);
    void onHttpError(int code);
#ifdef HAVE_CLIENT_SSO_SUPPORT
    bool getShibLoginUrl(const QString& last_shib_url, QUrl *url_out);
#endif // HAVE_CLIENT_SSO_SUPPORT

    QUrl url_;
    QUrl sso_server_;
    QString username_;
    QString password_;
    QString sso_token_;
    QString computer_name_;
    bool is_remember_device_;
    LoginRequest *request_;
    FetchAccountInfoRequest *account_info_req_;

    QString two_factor_auth_token_;
    QTimer client_sso_timer_;
    bool client_sso_success_;

    // Mutual TLS widgets (added programmatically into the login form grid).
    QCheckBox *mtls_enable_;
    QLineEdit *mtls_cert_;
    QLineEdit *mtls_key_;
    QLineEdit *mtls_password_;
    QLabel *mtls_cert_label_;
    QLabel *mtls_key_label_;
    QLabel *mtls_password_label_;
    QWidget *mtls_cert_row_;
    QWidget *mtls_key_row_;
    QWidget *mtls_password_row_;

#ifdef HAVE_SHIBBOLETH_SUPPORT
    LoginMode mode_;
#endif // HAVE_SHIBBOLETH_SUPPORT
};

#endif // SEAFILE_CLIENT_LOGIN_DIALOG_H

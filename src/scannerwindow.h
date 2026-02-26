#pragma once

#include <QFutureWatcher>
#include <QHash>
#include <QHostAddress>
#include <QIcon>
#include <QList>
#include <QMainWindow>
#include <QMap>
#include <QRegularExpression>
#include <QSet>
#include <QString>
#include <QStringList>

#include <atomic>
#include <functional>
#include <memory>

class QComboBox;
class QCompleter;
class QLabel;
class QLineEdit;
class QHBoxLayout;
class QPoint;
class QProgressBar;
class QPushButton;
class QToolBar;
class QSplitter;
class QStringListModel;
class QTableWidget;
class QTextEdit;
class QAction;
class QCloseEvent;
class QWidget;

struct ServiceHit {
    QString id;
    QString label;
    int port = 0;
    bool isWeb = false;
};

struct ScanResult {
    QString ip;
    QString mac;
    QString vendor;
    QString hostname;
    QList<ServiceHit> services;
    QString detailsText;
};

class ScannerWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit ScannerWindow(QWidget *parent = nullptr);
    ~ScannerWindow() override = default;

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void startScan();
    void finishScan();
    void updateProgress(int current, int total);
    void addOrUpdateResultRow(const ScanResult &result);
    void showTableContextMenu(const QPoint &pos);
    void copySelectedCell();
    void refreshAdapters();
    void applyDefaultTargets();
    void exportCsv();
    void printTable();
    void showSettingsDialog();
    void showAboutDialog();
    void updateWorkerLabel(int value);
    void handleTableDoubleClick(int row, int column);
    void showHeaderContextMenu(const QPoint &pos);
    void toggleSearchBar();

private:
    enum ColumnIndex {
        ColIp = 0,
        ColHostname = 1,
        ColMac = 2,
        ColVendor = 3,
        ColServices = 4,
        ColCount = 5
    };

    enum MacDisplayFormat {
        MacColonUpper = 0,
        MacColonLower = 1,
        MacHyphenUpper = 2,
        MacHyphenLower = 3,
        MacCiscoDot = 4,
        MacPlainUpper = 5,
        MacPlainLower = 6
    };

    struct NetworkTarget {
        QHostAddress baseAddress;
        int prefixLength = 24;
        QString interfaceName;
        QString interfaceLabel;
        QString localIp;
        QString localMac;
    };

    struct AdapterInfo {
        QString interfaceName;
        QString interfaceLabel;
        QString localIp;
        QString localMac;
    };

    struct ServiceDefinition {
        QString id;
        QString label;
        int port = 0;
        bool defaultEnabled = false;
        bool isWeb = false;
    };

    QList<NetworkTarget> detectDefaultNetworks() const;
    QList<AdapterInfo> buildAdapters(const QList<NetworkTarget> &targets) const;
    QString buildDefaultTargetText(const QList<NetworkTarget> &targets) const;
    QList<QHostAddress> parseTargetsInput(const QString &text, QString *error) const;
    QList<QHostAddress> hostsForCidr(const QHostAddress &base, int prefixLength) const;
    QList<QHostAddress> hostsForRangeToken(const QString &token, QString *error) const;

    QList<ScanResult> scanHosts(const AdapterInfo &adapter,
                                const QList<QHostAddress> &hosts,
                                const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                const std::function<void(int, int)> &onProgress,
                                const std::function<void(const ScanResult &)> &onResult) const;
    bool pingHost(const QHostAddress &address, const QString &interfaceName) const;
    QString lookupMacAddress(const QString &ip, const QString &interfaceName) const;
    QString lookupVendor(const QString &mac) const;
    QString lookupHostname(const QString &ip) const;
    QString lookupMdnsHostname(const QString &ip) const;
    QString lookupGatewayIp(const QString &interfaceName) const;

    QList<ServiceDefinition> availableServices() const;
    QList<ServiceHit> probeServices(const QString &ip,
                                    const std::shared_ptr<std::atomic_bool> &cancelRequested) const;
    QString collectDeviceDetails(const ScanResult &result) const;
    QString fetchTcpBanner(const QString &ip, int port, int timeoutMs, const QByteArray &prologue = {}) const;
    QString extractHttpServerHeader(const QString &rawResponse) const;
    QString inferOsFromSignals(const QStringList &signalList) const;
    void updateDetailsPaneForCurrentSelection();
    bool isPortOpen(const QString &ip, int port, int timeoutMs = 280) const;
    QString serviceText(const QList<ServiceHit> &services) const;
    QString formatMacForDisplay(const QString &mac) const;
    void refreshDisplayedMacAddresses();
    void applyTableFilters();
    bool rowMatchesFilters(int row) const;
    void openService(const QString &ip, const ServiceHit &service);

    void setupMenuBar();
    void loadOuiDatabase();
    QList<int> visibleColumnsInDisplayOrder() const;
    void copyCellText(int row, int column) const;
    QString cellText(int row, int column) const;
    void showStatusMessage(const QString &text);
    void applyTableColumnSizing();
    static QString normalizeOuiPrefix(const QString &prefix);
    static QString normalizeMacHex12(const QString &mac);
    QString accuracyLabel() const;
    int pingAttempts() const;
    int pingTimeoutSeconds() const;
    int serviceAttempts() const;
    int serviceTimeoutMs() const;
    void applyDefaultSettings();
    void loadSettings();
    void saveSettings() const;
    static bool isSafeTextInput(const QString &text, int maxLength);
    void recordTargetHistory(const QString &text);
    void setDetailsPaneVisible(bool visible);
    void rebuildMainToolbar();
    void applyToolbarDisplayMode();
    bool openPreferredTerminal(const QStringList &args = {}) const;
    QString preferredTerminalProgram() const;
    int findRowByIp(const QString &ip) const;

    static quint32 ipv4ToInt(const QHostAddress &address);
    static QHostAddress intToIpv4(quint32 value);
    static QString hexGatewayToIp(const QString &hexGateway);
    static bool parseIpv4(const QString &text, quint32 *out);
    static QString csvEscape(const QString &text);
    static QIcon createPlayIcon();
    static QIcon createStopIcon();

    QLineEdit *targetInput_ = nullptr;
    QPushButton *defaultsButton_ = nullptr;
    QComboBox *adapterCombo_ = nullptr;
    QPushButton *refreshAdaptersButton_ = nullptr;
    QPushButton *terminalButton_ = nullptr;
    QPushButton *findButton_ = nullptr;
    QPushButton *scanButton_ = nullptr;
    QToolBar *mainToolbar_ = nullptr;
    QWidget *toolbarContainer_ = nullptr;
    QHBoxLayout *toolbarLayout_ = nullptr;
    QLabel *targetsLabel_ = nullptr;
    QLabel *adapterLabel_ = nullptr;
    QTableWidget *table_ = nullptr;
    QWidget *searchBar_ = nullptr;
    QComboBox *searchScopeCombo_ = nullptr;
    QLineEdit *searchInput_ = nullptr;
    QSplitter *resultsSplitter_ = nullptr;
    QTextEdit *detailsPane_ = nullptr;

    QLabel *statusTextLabel_ = nullptr;
    QProgressBar *statusProgressBar_ = nullptr;

    QList<NetworkTarget> networkTargets_;
    QList<AdapterInfo> adapters_;
    QString defaultTargetText_;
    bool userCustomizedTargets_ = false;

    int maxParallelProbes_ = 4;
    int accuracyLevel_ = 2; // 0=Fast, 1=Balanced, 2=High, 3=Maximum
    int toolbarDisplayMode_ = 0; // legacy default
    int macDisplayFormat_ = MacColonUpper;
    QMap<QString, int> toolbarItemDisplayModes_;
    QStringList toolbarOrder_;
    QSet<QString> enabledServiceIds_;
    QHash<QString, QString> customCommands_;
    QHash<QString, QString> builtInOuiVendors_;
    QHash<QString, QString> customOuiVendors_;

    std::shared_ptr<std::atomic_bool> cancelRequested_;
    QHash<QString, QList<ServiceHit>> servicesByIp_;
    QHash<QString, QString> detailsByIp_;
    QFutureWatcher<QList<ScanResult>> scanWatcher_;
    bool scanInProgress_ = false;

    QIcon playIcon_;
    QIcon stopIcon_;
    QStringList targetHistory_;
    QCompleter *targetCompleter_ = nullptr;
    QStringListModel *targetHistoryModel_ = nullptr;
    QAction *showDetailsPaneAction_ = nullptr;
};

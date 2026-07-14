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

#include "scanoptions.h"
#include "scanbudget.h"
#include "neighborentry.h"
#include "scanresult.h"
#include "serviceevidence.h"
#include "targetdefaults.h"

class QComboBox;
class QCompleter;
class QLabel;
class QLineEdit;
class QHBoxLayout;
class QPoint;
class QProgressBar;
class QSettings;
class QPushButton;
class QToolBar;
class QSplitter;
class QStringListModel;
class QTableView;
class QTcpSocket;
class QTextEdit;
class QTimer;
class QAction;
class QCloseEvent;
class QWidget;
struct ScannerWindowTestAccess;
class ResultTableModel;
class ServiceTagDelegate;
class ScanMdnsResolver;

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
    void queueResultForDisplay(const ScanResult &result);
    void flushPendingResults();
    void beginScanCompletionPresentation(const QList<ScanResult> &finalResults,
                                         bool wasCanceled);
    void completeScanPresentation();
    void showTableContextMenu(const QPoint &pos);
    void copySelectedCell();
    void refreshAdapters();
    void applyDefaultTargets();
    void exportCsv();
    void printTable();
    void showSettingsDialog();
    void showHelpDialog();
    void showAboutDialog();
    void showResolverDiagnostics();
    void updateWorkerLabel(int value);
    void handleTableDoubleClick(int row, int column);
    void showHeaderContextMenu(const QPoint &pos);
    void toggleSearchBar();

private:
    friend struct ScannerWindowTestAccess;

    // Table column order and logical ids used across sorting/filtering/export.
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
        // Network base and prefix selected for scanning.
        QHostAddress baseAddress;
        int prefixLength = 24;
        // Interface metadata used to route probes correctly.
        QString interfaceName;
        QString interfaceLabel;
        QString localIp;
        QString localMac;
    };

    struct AdapterInfo {
        // Interface identity and source address used for scans.
        QString interfaceName;
        QString interfaceLabel;
        QString localIp;
        QString localMac;
        QStringList dnsSuffixes;
        bool isPhysical = false;
        bool isRoutable = false;
        bool hasDefaultRoute = false;
    };

    struct ServiceDefinition {
        // Static service config for probe UI and execution.
        QString id;
        QString label;
        int port = 0;
        bool defaultEnabled = false;
        bool isWeb = false;
    };

    struct ViewportAnchor {
        QString identity;
        int pixelOffset = 0;
        int scrollValue = 0;
    };

    struct HostnameResolution {
        QList<HostnameEvidence> evidence;
        QList<ResolverEvent> resolverEvents;
    };

    // Detect routable IPv4 networks and build initial scan defaults.
    QList<NetworkTarget> detectDefaultNetworks() const;
    QList<AdapterInfo> buildAdapters() const;
    DefaultTargetPlan buildDefaultTargetPlanForNetworks(
        const QList<NetworkTarget> &targets) const;
    DefaultTargetPlan buildDefaultTargetPlanForAdapter(const QString &interfaceName) const;
    int resolveAdapterIndexForTargets(const QList<QHostAddress> &hosts) const;
    int preferredAdapterIndex() const;

    // Parse user target syntax (CIDR/range/single IP) into host addresses.
    QList<QHostAddress> parseTargetsInput(const QString &text, QString *error) const;
    QList<QHostAddress> hostsForCidr(const QHostAddress &base, int prefixLength) const;
    QList<QHostAddress> hostsForRangeToken(const QString &token, QString *error) const;

    // Main worker entry point for host discovery and enrichment.
    QList<ScanResult> scanHosts(const ScanOptions &options,
                                const QList<QHostAddress> &hosts,
                                const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                const std::function<void(int, int)> &onProgress,
                                const std::function<void(const ScanResult &)> &onResult) const;
    void startDebugScan();
    QList<ScanResult> runDebugScan(
        int accuracyLevel,
        const std::shared_ptr<std::atomic_bool> &cancelRequested,
        const std::function<void(int, int)> &onProgress,
        const std::function<void(const ScanResult &)> &onResult) const;

    // Host discovery helpers.
    bool pingHost(const QHostAddress &address,
                  const ScanOptions &options,
                  const TargetBudget &budget,
                  const std::shared_ptr<std::atomic_bool> &cancelRequested) const;
    NeighborObservation lookupNeighbor(const QString &ip,
                                       const QString &interfaceName,
                                       const TargetBudget &budget,
                                       const std::shared_ptr<std::atomic_bool> &cancelRequested) const;
    NeighborObservation confirmNeighborLiveness(
        const NeighborObservation &initial,
        const QString &ip,
        const QString &interfaceName,
        const ScanOptions &options,
        const TargetBudget &budget,
        const std::shared_ptr<std::atomic_bool> &cancelRequested) const;
    QString lookupVendor(const QString &mac, const ScanOptions &options) const;
    HostnameResolution lookupHostname(
        const QString &ip,
        const HostnameEvidence &preliminary,
        const QStringList &adapterDnsSuffixes,
        int accuracyLevel,
        const TargetBudget &budget,
        const std::shared_ptr<std::atomic_bool> &cancelRequested,
        ScanMdnsResolver &mdnsResolver) const;
    QString lookupGatewayIp(const QString &interfaceName) const;

    // Service detection and details enrichment.
    QList<ServiceDefinition> availableServices() const;
    QList<ServiceHit> probeServices(const QString &ip,
                                    const QString &localBindIp,
                                    const TargetBudget &budget,
                                    const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                    const ScanOptions &options) const;
    QString collectDeviceDetails(const ScanResult &result, const ScanOptions &options) const;
    bool probePlainService(const ServiceDefinition &definition,
                           const QString &ip,
                           const QString &localBindIp,
                           const TargetBudget &budget,
                           const std::shared_ptr<std::atomic_bool> &cancelRequested,
                           const ScanOptions &options,
                           ServiceEvidenceLevel *evidence) const;
    bool probeTlsService(const ServiceDefinition &definition,
                         const QString &ip,
                         const QString &localBindIp,
                         const TargetBudget &budget,
                         const std::shared_ptr<std::atomic_bool> &cancelRequested,
                         const ScanOptions &options,
                         ServiceEvidenceLevel *evidence) const;
    QByteArray readServiceResponse(
        QTcpSocket &socket,
        const TargetBudget &budget,
        const std::shared_ptr<std::atomic_bool> &cancelRequested,
        int timeoutMs,
        bool smtpMultiline = false) const;
    void updateDetailsPaneForCurrentSelection();
    QList<ResolverEvent> resolverEventsForDisplayedResults() const;
    QByteArray resolverSupportBundle() const;
    QString serviceText(const QList<ServiceHit> &services) const;
    QString formatMacForDisplay(const QString &mac) const;
    QString formatMacForDisplay(const QString &mac, int displayFormat) const;
    void refreshDisplayedMacAddresses();
    void applyTableFilters();
    bool rowMatchesFilters(int row) const;
    void openService(const QString &ip, const ServiceHit &service);

    // UI wiring/persistence helpers.
    void setupMenuBar();
    void loadOuiDatabase();
    QList<int> visibleColumnsInDisplayOrder() const;
    void copyCellText(int row, int column) const;
    QString cellText(int row, int column) const;
    void showStatusMessage(const QString &text);
    void applyTableColumnSizing();
    static QString normalizeOuiPrefix(const QString &prefix);
    static QString normalizeMacHex12(const QString &mac);
    static QHash<QString, QStringList> parseAdapterDnsDomains(
        const QByteArray &json);
    QString accuracyLabel() const;
    ScanOptions captureScanOptions(const AdapterInfo &adapter) const;
    void applyDefaultSettings();
    void loadSettings();
    void saveSettings() const;
    void scheduleSettingsSave();
    static void migrateSettings(QSettings &settings);
    static bool parseCustomOuiOverrides(const QString &text,
                                        QHash<QString, QString> *vendors,
                                        QString *error);
    static bool isSafeTextInput(const QString &text, int maxLength);
    void recordTargetHistory(const QString &text);
    void setDetailsPaneVisible(bool visible);
    void rebuildMainToolbar();
    void applyToolbarDisplayMode();
    bool openPreferredTerminal(const QStringList &args = {}, QString *error = nullptr) const;
    QString preferredTerminalProgram() const;
    QString rowIdentityKey(int row) const;
    int findRowByIdentity(const QString &identityKey) const;
    ViewportAnchor captureViewportAnchor() const;
    void restoreViewportAnchor(const ViewportAnchor &anchor);
    void validateTargetLimitFeedback(const QString &text);

    // Utility conversion helpers.
    static quint32 ipv4ToInt(const QHostAddress &address);
    static QHostAddress intToIpv4(quint32 value);
    static QString hexGatewayToIp(const QString &hexGateway);
    static bool parseIpv4(const QString &text, quint32 *out);
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
    QTableView *table_ = nullptr;
    ResultTableModel *resultModel_ = nullptr;
    ServiceTagDelegate *serviceTagDelegate_ = nullptr;
    QWidget *searchBar_ = nullptr;
    QComboBox *searchScopeCombo_ = nullptr;
    QLineEdit *searchInput_ = nullptr;
    QSplitter *resultsSplitter_ = nullptr;
    QTextEdit *detailsPane_ = nullptr;

    QLabel *statusTextLabel_ = nullptr;
    QProgressBar *statusProgressBar_ = nullptr;

    QList<NetworkTarget> networkTargets_;
    QString defaultTargetNotice_;
    QString appliedDefaultTargetNotice_;
    QList<AdapterInfo> adapters_;
    QString defaultTargetText_;
    bool userCustomizedTargets_ = false;
    bool targetLimitWarningActive_ = false;
    bool rememberLastTargetOnLaunch_ = false;
    QString pendingLastTarget_;
    TargetTextFormat targetTextFormat_ = TargetTextFormat::Cidr;

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
    QList<ScanResult> pendingDisplayResults_;
    QTimer *resultFlushTimer_ = nullptr;
    QTimer *settingsSaveTimer_ = nullptr;
    QFutureWatcher<QList<ScanResult>> scanWatcher_;
    bool scanCompletionPending_ = false;
    bool completedScanWasCanceled_ = false;
    bool scanInProgress_ = false;
    bool closePending_ = false;

    QIcon playIcon_;
    QIcon stopIcon_;
    QStringList targetHistory_;
    QCompleter *targetCompleter_ = nullptr;
    QStringListModel *targetHistoryModel_ = nullptr;
    QAction *showDetailsPaneAction_ = nullptr;
    QAction *rememberLastTargetAction_ = nullptr;
};

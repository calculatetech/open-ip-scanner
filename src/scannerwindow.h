#pragma once

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
#include "diagnostics.h"
#include "devicepresentation.h"
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
class QTextEdit;
class QTextBrowser;
class QTimer;
class QAction;
class QCloseEvent;
class QWidget;
class QUrl;
struct ScannerWindowTestAccess;
struct CsvExportData;
class ResultTableModel;
class ServiceTagDelegate;
class ScanSession;

class ScannerWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit ScannerWindow(QWidget *parent = nullptr);
    ~ScannerWindow() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void startScan();
    void finishScan(const QList<ScanResult> &finalResults, bool wasCanceled);
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

    struct ViewportAnchor {
        QString identity;
        int pixelOffset = 0;
        int scrollValue = 0;
    };

    using ProductionScanRunner = std::function<QList<ScanResult>(
        const ScanOptions &,
        const QList<QHostAddress> &,
        const std::shared_ptr<std::atomic_bool> &,
        const std::function<void(int, int)> &,
        const std::function<void(const ScanResult &)> &)>;

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

    void startDebugScan();

    // Service detection and details enrichment.
    void updateDetailsPaneForCurrentSelection();
    QList<ResolverEvent> resolverEventsForDisplayedResults() const;
    QByteArray resolverSupportBundle() const;
    QMap<QString, bool> diagnosticCapabilities() const;
    QString serviceText(const QList<ServiceHit> &services) const;
    QString formatMacForDisplay(const QString &mac) const;
    QString formatMacForDisplay(const QString &mac, int displayFormat) const;
    void refreshDisplayedMacAddresses();
    void applyTableFilters();
    bool rowMatchesFilters(int row) const;
    void openService(const QString &ip, const ServiceHit &service);
    bool exportCsvToPath(const QString &path, const CsvExportData &data);
    bool saveSupportBundleToPath(const QString &path);

    // UI wiring/persistence helpers.
    void setupMenuBar();
    void loadOuiDatabase();
    QList<int> visibleColumnsInDisplayOrder() const;
    void copyCellText(int row, int column) const;
    QString cellText(int row, int column) const;
    void showStatusMessage(const QString &text);
    void applyTableColumnSizing();
    static QString normalizeOuiPrefix(const QString &prefix);
    static QHash<QString, QStringList> parseAdapterDnsDomains(
        const QByteArray &json);
    QString accuracyLabel() const;
    ScanOptions captureScanOptions(const AdapterInfo &adapter) const;
    void applyDefaultSettings();
    void loadSettings();
    void saveSettings() const;
    void scheduleSettingsSave();
    static bool migrateSettings(QSettings &settings, QString *error = nullptr);
    static bool parseCustomOuiOverrides(const QString &text,
                                        QHash<QString, QString> *vendors,
                                        QString *error);
    static bool isSafeTextInput(const QString &text, int maxLength);
    bool recordTargetHistory(const QString &text);
    void setTargetHistoryRetention(bool enabled);
    void clearTargetHistory();
    QString activeProbeSummary(bool detailed = false) const;
    QString aboutText() const;
    QString probeSummary(const ScanOptions &options,
                         bool detailed,
                         bool targetRetained) const;
    bool confirmScanAuthorization(const ScanOptions &options);
    static bool clearRetainedTargetSettings(QSettings &settings,
                                            bool disableRetention,
                                            QString *error);
    static bool persistTargetHistorySettings(QSettings &settings,
                                             const QStringList &history,
                                             const QString &lastInput,
                                             bool rememberLast,
                                             QString *error);
    void updateProbeSummary();
    void setDetailsPaneVisible(bool visible);
    int defaultDetailsPaneHeight() const;
    void applyDetailsPaneHeight();
    void configureExternalLinks(QTextBrowser *browser);
    void openExternalLink(const QUrl &url);
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
    int detailsPaneHeight_ = 0;

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
    bool saveTargetHistory_ = false;
    bool diagnosticLoggingEnabled_ = false;
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
    QString ouiDatabaseVersion_ = "Unavailable";

    ScanSession *scanSession_ = nullptr;
    ProductionScanRunner productionScanRunner_;
    std::function<bool(const QUrl &)> urlLauncher_;
    std::function<bool(const QString &, const QStringList &)> detachedLauncher_;
    QList<ScanResult> pendingDisplayResults_;
    QHash<QString, int> pendingDisplayIdentityRows_;
    QTimer *resultFlushTimer_ = nullptr;
    int tableFilterApplicationCount_ = 0;
    QTimer *settingsSaveTimer_ = nullptr;
    bool scanCompletionPending_ = false;
    bool completedScanWasCanceled_ = false;
    bool scanInProgress_ = false;
    bool hasActiveScanOptions_ = false;
    bool activeScanTargetRetained_ = false;
    ScanOptions activeScanOptions_;
    bool closePending_ = false;

    QIcon playIcon_;
    QIcon stopIcon_;
    QStringList targetHistory_;
    QCompleter *targetCompleter_ = nullptr;
    QStringListModel *targetHistoryModel_ = nullptr;
    QAction *showDetailsPaneAction_ = nullptr;
    QAction *rememberLastTargetAction_ = nullptr;
    QAction *saveTargetHistoryAction_ = nullptr;
    QAction *clearTargetHistoryAction_ = nullptr;
    QLabel *probeSummaryLabel_ = nullptr;
};

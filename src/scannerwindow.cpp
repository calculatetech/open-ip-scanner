#include "scannerwindow.h"
#include "cancellablewait.h"
#include "csvexporter.h"
#include "debugscanfixture.h"
#include "mdnsresolver.h"
#include "ouidatabase.h"
#include "resulttablemodel.h"
#include "servicetagdelegate.h"
#include "settingslayout.h"
#include "settingsstore.h"
#include "targetparser.h"

#include <QAction>
#include <QAbstractButton>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QClipboard>
#include <QComboBox>
#include <QCompleter>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QElapsedTimer>
#include <QFrame>
#include <QFontDatabase>
#include <QFormLayout>
#include <QFontMetrics>
#include <QFuture>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHeaderView>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QHBoxLayout>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QPainter>
#include <QPrinter>
#include <QPrintDialog>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QRadioButton>
#include <QSaveFile>
#include <QScrollArea>
#include <QSet>
#include <QSettings>
#include <QSignalBlocker>
#include <QShortcut>
#include <QSlider>
#include <QProcessEnvironment>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStyle>
#include <QSysInfo>
#include <QStringListModel>
#include <QTableView>
#include <QTcpSocket>
#include <QSslError>
#include <QSslSocket>
#include <QTextEdit>
#include <QTextDocument>
#include <QTextBrowser>
#include <QPlainTextEdit>
#include <QTextStream>
#include <QThreadPool>
#include <QTimer>
#include <QToolBar>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>
#include <QScrollBar>
#include <QtConcurrent>

#include <algorithm>
#include <atomic>
#include <limits>

namespace {
constexpr int kMaxHostsToScan = 4096;
constexpr int kMaxParallelProbes = 16;
constexpr int kSettingsSchemaVersion = 3;
constexpr int kSettingsSaveDebounceMs = 350;
constexpr int kAuthorizationAcknowledgementVersion = 1;
// Default toolbar layout used on first launch and settings reset.
const QStringList kToolbarDefaultOrder = {
    "targets_label", "target_input", "scan", "sep", "auto", "find", "terminal", "sep", "adapter_label", "adapter_combo", "refresh"
};
const QSet<QString> kToolbarAllowedIds = {
    "targets_label", "target_input", "scan", "sep", "spacer", "auto", "find", "terminal", "adapter_label", "adapter_combo", "refresh"
};
const QSet<QString> kToolbarButtonIds = {"scan", "auto", "find", "terminal", "refresh"};

bool isLinkLocalIpv4(quint32 value)
{
    return (value & 0xFFFF0000u) == 0xA9FE0000u;
}

bool hasDefaultRoute(const QString &interfaceName)
{
#ifdef Q_OS_LINUX
    QFile routeFile("/proc/net/route");
    if (!routeFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }
    while (!routeFile.atEnd()) {
        const QString line = QString::fromUtf8(routeFile.readLine()).trimmed();
        if (line.isEmpty() || line.startsWith("Iface")) {
            continue;
        }
        const QStringList fields = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (fields.size() < 2) {
            continue;
        }
        if (fields[0] == interfaceName && fields[1] == "00000000") {
            return true;
        }
    }
#else
    Q_UNUSED(interfaceName)
#endif
    return false;
}

bool isLikelyVirtualInterface(const QNetworkInterface &iface)
{
    const QString name = iface.name().toLower();
    const QString label = iface.humanReadableName().toLower();
    const QString blob = name + " " + label;
    static const QStringList virtualHints = {
        "docker", "veth", "virbr", "vmnet", "vbox", "virtual", "bridge", "br-", "tun", "tap", "wg", "zt"
    };
    for (const QString &hint : virtualHints) {
        if (blob.contains(hint)) {
            return true;
        }
    }
    const auto flags = iface.flags();
    if (flags & QNetworkInterface::IsPointToPoint) {
        return true;
    }
    const QString mac = iface.hardwareAddress().trimmed();
    if (mac.isEmpty() || mac == "00:00:00:00:00:00") {
        return true;
    }
    return false;
}
}

ScannerWindow::ScannerWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("Open IP Scanner");
    resize(1040, 620);

    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    targetInput_ = new QLineEdit(central);
    targetInput_->setPlaceholderText("Examples: 192.168.1.0/24, 10.0.0.10-10.0.0.50, 10.0.0.10-50, 10.0.1.20");
    targetInput_->setMaxLength(2048);
    targetInput_->setValidator(new QRegularExpressionValidator(
        QRegularExpression("^(?:[0-9.,/\\-\\s]*|test)$"), targetInput_));
    targetHistoryModel_ = new QStringListModel(this);
    targetCompleter_ = new QCompleter(targetHistoryModel_, this);
    targetCompleter_->setCaseSensitivity(Qt::CaseInsensitive);
    targetCompleter_->setFilterMode(Qt::MatchContains);
    targetInput_->setCompleter(targetCompleter_);
    defaultsButton_ = new QPushButton("Auto", central);
    defaultsButton_->setIcon(style()->standardIcon(QStyle::SP_DriveNetIcon));
    defaultsButton_->setToolTip("Scan connected network(s) of selected adapter");

    findButton_ = new QPushButton("Find", central);
    findButton_->setIcon(QIcon::fromTheme("edit-find", style()->standardIcon(QStyle::SP_FileDialogContentsView)));
    findButton_->setToolTip("Show search/filter bar");
    findButton_->setFixedWidth(32);

    adapterCombo_ = new QComboBox(central);
    refreshAdaptersButton_ = new QPushButton(central);
    refreshAdaptersButton_->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    refreshAdaptersButton_->setToolTip("Refresh adapters");
    refreshAdaptersButton_->setFixedWidth(32);

    terminalButton_ = new QPushButton("Terminal", central);
    terminalButton_->setIcon(QIcon::fromTheme("utilities-terminal", style()->standardIcon(QStyle::SP_ComputerIcon)));
    terminalButton_->setToolTip("Open default terminal");

    playIcon_ = createPlayIcon();
    stopIcon_ = createStopIcon();
    scanButton_ = new QPushButton(central);
    scanButton_->setIcon(playIcon_);
    scanButton_->setToolTip("Start scan");
    scanButton_->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);

    resultModel_ = new ResultTableModel(this);
    resultModel_->setMacFormatter([this](const QString &mac) {
        return formatMacForDisplay(mac);
    });
    table_ = new QTableView(central);
    table_->setModel(resultModel_);
    serviceTagDelegate_ = new ServiceTagDelegate(table_);
    table_->setItemDelegateForColumn(ColServices, serviceTagDelegate_);
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectItems);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->setSortingEnabled(true);
    table_->setWordWrap(false);
    table_->setTextElideMode(Qt::ElideRight);
    table_->horizontalHeader()->setSortIndicatorShown(true);
    table_->sortByColumn(ColIp, Qt::AscendingOrder);
    table_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    table_->setFrameShape(QFrame::StyledPanel);
    table_->setFrameShadow(QFrame::Plain);
    table_->setLineWidth(1);
    table_->horizontalHeader()->setStretchLastSection(false);
    table_->horizontalHeader()->setSectionResizeMode(ColIp, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(ColHostname, QHeaderView::Interactive);
    table_->horizontalHeader()->setSectionResizeMode(ColMac, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(ColVendor, QHeaderView::Interactive);
    table_->horizontalHeader()->setSectionResizeMode(ColServices, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionsMovable(true);
    table_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

    table_->setStyleSheet(
        "QTableView {"
        "  border: 1px solid palette(midlight);"
        "  border-radius: 3px;"
        "  gridline-color: transparent;"
        "}"
        "QTableView::item {"
        "  border: 0px;"
        "}"
        "QTableView::item:selected {"
        "  background-color: #1769d1;"
        "  color: #ffffff;"
        "  border: 0px;"
        "}"
        "QTableView::item:selected:!active {"
        "  background-color: #2f4f7a;"
        "  color: #ffffff;"
        "  border: 0px;"
        "}");

    mainToolbar_ = addToolBar("Main");
    mainToolbar_->setObjectName("main_toolbar");
    mainToolbar_->setMovable(false);
    mainToolbar_->setFloatable(false);
    mainToolbar_->setAllowedAreas(Qt::TopToolBarArea);

    targetsLabel_ = new QLabel("Targets:", this);
    adapterLabel_ = new QLabel("Adapter:", this);
    targetInput_->setMinimumWidth(320);
    targetInput_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    adapterCombo_->setMinimumWidth(220);
    adapterCombo_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    toolbarContainer_ = new QWidget(mainToolbar_);
    toolbarContainer_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    toolbarLayout_ = new QHBoxLayout(toolbarContainer_);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);
    mainToolbar_->addWidget(toolbarContainer_);

    toolbarOrder_ = kToolbarDefaultOrder;
    rebuildMainToolbar();

    searchBar_ = new QWidget(central);
    auto *searchLayout = new QHBoxLayout(searchBar_);
    searchLayout->setContentsMargins(4, 2, 4, 2);
    searchLayout->setSpacing(6);
    searchScopeCombo_ = new QComboBox(searchBar_);
    searchScopeCombo_->addItem("All", "all");
    searchScopeCombo_->addItem("IP", "ip");
    searchScopeCombo_->addItem("Hostname", "hostname");
    searchScopeCombo_->addItem("MAC", "mac");
    searchScopeCombo_->addItem("Vendor", "vendor");
    searchScopeCombo_->addItem("Services", "services");
    searchScopeCombo_->addItem("OUI Prefix", "oui");
    searchInput_ = new QLineEdit(searchBar_);
    searchInput_->setPlaceholderText("Filter (e.g. intel, ssh, 00:90:7F)");
    auto *searchClearButton = new QPushButton("Clear", searchBar_);
    searchLayout->addWidget(new QLabel("Find:", searchBar_));
    searchLayout->addWidget(searchScopeCombo_);
    searchLayout->addWidget(searchInput_, 1);
    searchLayout->addWidget(searchClearButton);
    searchBar_->setVisible(false);

    auto *tablePane = new QWidget(central);
    auto *tablePaneLayout = new QVBoxLayout(tablePane);
    tablePaneLayout->setContentsMargins(0, 0, 0, 0);
    tablePaneLayout->setSpacing(0);
    tablePaneLayout->addWidget(searchBar_);
    tablePaneLayout->addWidget(table_, 1);

    resultsSplitter_ = new QSplitter(Qt::Vertical, central);
    resultsSplitter_->setChildrenCollapsible(false);
    resultsSplitter_->addWidget(tablePane);

    detailsPane_ = new QTextEdit(resultsSplitter_);
    detailsPane_->setReadOnly(true);
    detailsPane_->setPlaceholderText("Select a device to view details.");
    detailsPane_->setVisible(false);
    resultsSplitter_->addWidget(detailsPane_);
    resultsSplitter_->setStretchFactor(0, 1);
    resultsSplitter_->setStretchFactor(1, 0);

    layout->addWidget(resultsSplitter_, 1);

    setCentralWidget(central);

    statusTextLabel_ = new QLabel(this);
    probeSummaryLabel_ = new QLabel(this);
    probeSummaryLabel_->setObjectName("probeSummaryLabel");
    statusProgressBar_ = new QProgressBar(this);
    statusProgressBar_->setMinimumWidth(240);
    statusProgressBar_->setVisible(false);
    statusBar()->addWidget(statusTextLabel_, 1);
    statusBar()->addPermanentWidget(probeSummaryLabel_);
    statusBar()->addPermanentWidget(statusProgressBar_);

    resultFlushTimer_ = new QTimer(this);
    resultFlushTimer_->setSingleShot(true);
    resultFlushTimer_->setInterval(16);
    settingsSaveTimer_ = new QTimer(this);
    settingsSaveTimer_->setSingleShot(true);
    settingsSaveTimer_->setInterval(kSettingsSaveDebounceMs);
    connect(settingsSaveTimer_, &QTimer::timeout,
            this, &ScannerWindow::saveSettings);

    applyDefaultSettings();
    loadOuiDatabase();
    // Internal overrides for local environments and virtual adapters.
    builtInOuiVendors_.insert("00163E", "Xensource");
    builtInOuiVendors_.insert("000C29", "VMware");
    builtInOuiVendors_.insert("001C42", "Parallels");
    builtInOuiVendors_.insert("080027", "Oracle VirtualBox");

    setupMenuBar();
    loadSettings();
    updateProbeSummary();
    refreshAdapters();
    if (rememberLastTargetOnLaunch_ && !pendingLastTarget_.isEmpty()) {
        targetInput_->setText(pendingLastTarget_);
        userCustomizedTargets_ = true;
        validateTargetLimitFeedback(targetInput_->text());
    }
    applyTableColumnSizing();

    connect(scanButton_, &QPushButton::clicked, this, &ScannerWindow::startScan);
    connect(terminalButton_, &QPushButton::clicked, this, [this]() {
        QString error;
        if (!openPreferredTerminal({}, &error)) {
            const QString detail = error.isEmpty() ? "Could not launch default terminal." : error;
            QMessageBox::warning(this, "Terminal", detail);
            showStatusMessage(detail);
        }
    });
    connect(refreshAdaptersButton_, &QPushButton::clicked, this, &ScannerWindow::refreshAdapters);
    connect(findButton_, &QPushButton::clicked, this, &ScannerWindow::toggleSearchBar);
    connect(defaultsButton_, &QPushButton::clicked, this, &ScannerWindow::applyDefaultTargets);
    connect(targetInput_, &QLineEdit::textEdited, this, [this]() {
        userCustomizedTargets_ = true;
    });
    connect(targetInput_, &QLineEdit::textChanged, this, &ScannerWindow::validateTargetLimitFeedback);
    connect(targetInput_, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (saveTargetHistory_ && rememberLastTargetOnLaunch_) {
            scheduleSettingsSave();
        }
        if (!scanInProgress_) {
            scanButton_->setEnabled(!adapters_.isEmpty() ||
                                    isDebugScanFixtureTarget(text));
        }
    });
    connect(adapterCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        validateTargetLimitFeedback(targetInput_->text());
    });
    connect(targetInput_, &QLineEdit::returnPressed, this, &ScannerWindow::startScan);
    connect(&scanWatcher_, &QFutureWatcher<QList<ScanResult>>::finished, this, &ScannerWindow::finishScan);
    connect(table_, &QWidget::customContextMenuRequested, this, &ScannerWindow::showTableContextMenu);
    connect(table_->horizontalHeader(), &QWidget::customContextMenuRequested, this, &ScannerWindow::showHeaderContextMenu);
    connect(table_, &QTableView::doubleClicked, this, [this](const QModelIndex &index) {
        handleTableDoubleClick(index.row(), index.column());
    });
    connect(table_->selectionModel(), &QItemSelectionModel::currentChanged, this,
            [this](const QModelIndex &, const QModelIndex &) {
        updateDetailsPaneForCurrentSelection();
    });
    connect(serviceTagDelegate_, &ServiceTagDelegate::serviceActivated, this,
            [this](const QModelIndex &index, int serviceIndex) {
        const ScanResult result = resultModel_->resultAt(index.row());
        if (serviceIndex >= 0 && serviceIndex < result.services.size()) {
            openService(result.ip, result.services.at(serviceIndex));
        }
    });
    connect(resultModel_, &QAbstractItemModel::layoutChanged, this,
            [this]() { applyTableFilters(); });
    connect(resultFlushTimer_, &QTimer::timeout, this, &ScannerWindow::flushPendingResults);

    auto *copyShortcut = new QShortcut(QKeySequence::Copy, table_);
    connect(copyShortcut, &QShortcut::activated, this, &ScannerWindow::copySelectedCell);
    connect(searchInput_, &QLineEdit::textChanged, this, &ScannerWindow::applyTableFilters);
    connect(searchScopeCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        applyTableFilters();
    });
    connect(searchClearButton, &QPushButton::clicked, this, [this]() {
        searchInput_->clear();
        searchScopeCombo_->setCurrentIndex(0);
        applyTableFilters();
    });
}

void ScannerWindow::setupMenuBar()
{
    QMenu *fileMenu = menuBar()->addMenu("File");
    QAction *exportAction = fileMenu->addAction("Export CSV...");
    connect(exportAction, &QAction::triggered, this, &ScannerWindow::exportCsv);

    QAction *printAction = fileMenu->addAction("Print...");
    connect(printAction, &QAction::triggered, this, &ScannerWindow::printTable);

    fileMenu->addSeparator();
    QAction *quitAction = fileMenu->addAction("Quit");
    connect(quitAction, &QAction::triggered, this, &QWidget::close);

    QMenu *settingsMenu = menuBar()->addMenu("Settings");
    QAction *settingsAction = settingsMenu->addAction("Preferences...");
    connect(settingsAction, &QAction::triggered, this, &ScannerWindow::showSettingsDialog);
    settingsMenu->addSeparator();
    saveTargetHistoryAction_ = settingsMenu->addAction("Save Target History");
    saveTargetHistoryAction_->setCheckable(true);
    saveTargetHistoryAction_->setChecked(false);
    connect(saveTargetHistoryAction_, &QAction::toggled, this,
            [this](bool checked) { setTargetHistoryRetention(checked); });
    rememberLastTargetAction_ = settingsMenu->addAction("Remember Last Target On Launch");
    rememberLastTargetAction_->setCheckable(true);
    rememberLastTargetAction_->setChecked(false);
    connect(rememberLastTargetAction_, &QAction::toggled, this, [this](bool checked) {
        rememberLastTargetOnLaunch_ = saveTargetHistory_ && checked;
        saveSettings();
        updateProbeSummary();
    });
    rememberLastTargetAction_->setEnabled(false);
    clearTargetHistoryAction_ = settingsMenu->addAction("Clear Target History");
    clearTargetHistoryAction_->setEnabled(false);
    connect(clearTargetHistoryAction_, &QAction::triggered,
            this, &ScannerWindow::clearTargetHistory);
    settingsMenu->addSeparator();
    showDetailsPaneAction_ = settingsMenu->addAction("Show Details Pane");
    showDetailsPaneAction_->setCheckable(true);
    showDetailsPaneAction_->setChecked(false);
    connect(showDetailsPaneAction_, &QAction::toggled, this, [this](bool checked) {
        setDetailsPaneVisible(checked);
        saveSettings();
    });

    QMenu *helpMenu = menuBar()->addMenu("Help");
    QAction *diagnosticsAction = helpMenu->addAction("Hostname Diagnostics...");
    connect(diagnosticsAction,
            &QAction::triggered,
            this,
            &ScannerWindow::showResolverDiagnostics);
    QAction *usageAction = helpMenu->addAction("Usage Guide");
    connect(usageAction, &QAction::triggered, this, &ScannerWindow::showHelpDialog);
    QAction *aboutAction = helpMenu->addAction("About");
    connect(aboutAction, &QAction::triggered, this, &ScannerWindow::showAboutDialog);
}

void ScannerWindow::loadOuiDatabase()
{
    QStringList candidatePaths;
    candidatePaths << ":/data/oui.txt";
    candidatePaths << ":/data/../data/oui.txt"; // compatibility with older resource paths
    candidatePaths << (QCoreApplication::applicationDirPath() + "/oui.txt"); // fallback for dev/test

    QFile file;
    for (const QString &path : candidatePaths) {
        file.setFileName(path);
        if (file.exists() && file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            break;
        }
    }

    if (!file.isOpen()) {
        return;
    }

    const QRegularExpression reHex("^\\s*([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})\\s+\\(hex\\)\\s+(.+)$");
    const QRegularExpression reBase16("^\\s*([0-9A-Fa-f]{6})\\s+\\(base 16\\)\\s+(.+)$");

    while (!file.atEnd()) {
        const QString line = QString::fromUtf8(file.readLine()).trimmed();
        if (line.isEmpty()) {
            continue;
        }

        QRegularExpressionMatch match = reHex.match(line);
        if (!match.hasMatch()) {
            match = reBase16.match(line);
        }
        if (!match.hasMatch()) {
            continue;
        }

        const QString prefix = normalizeOuiPrefix(match.captured(1));
        const QString vendor = match.captured(2).trimmed();
        if (!prefix.isEmpty() && !vendor.isEmpty()) {
            builtInOuiVendors_.insert(prefix, vendor);
        }
    }
}

QList<ScannerWindow::NetworkTarget> ScannerWindow::detectDefaultNetworks() const
{
    QList<NetworkTarget> targets;

    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &iface : interfaces) {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) ||
            !(flags & QNetworkInterface::IsRunning) ||
            (flags & QNetworkInterface::IsLoopBack)) {
            continue;
        }

        for (const QNetworkAddressEntry &entry : iface.addressEntries()) {
            const QHostAddress ip = entry.ip();
            if (ip.protocol() != QAbstractSocket::IPv4Protocol) {
                continue;
            }

            if (ip.isNull() || ip.isLoopback() || ip.isMulticast()) {
                continue;
            }

            const quint32 value = ipv4ToInt(ip);
            if ((value & 0xFFFF0000u) == 0xA9FE0000u) {
                continue;
            }

            const int prefix = entry.prefixLength();
            if (prefix < 1 || prefix > 32) {
                continue;
            }

            const quint32 mask = 0xFFFFFFFFu << (32 - prefix);
            const quint32 network = value & mask;

            NetworkTarget target;
            target.baseAddress = intToIpv4(network);
            target.prefixLength = prefix;
            target.interfaceName = iface.name();
            target.interfaceLabel = iface.humanReadableName();
            target.localIp = ip.toString();
            target.localMac = iface.hardwareAddress().toUpper();
            targets.append(target);
        }
    }

    std::sort(targets.begin(), targets.end(), [](const NetworkTarget &a, const NetworkTarget &b) {
        if (a.interfaceLabel == b.interfaceLabel) {
            return a.localIp < b.localIp;
        }
        return a.interfaceLabel < b.interfaceLabel;
    });

    targets.erase(std::unique(targets.begin(), targets.end(), [](const NetworkTarget &a, const NetworkTarget &b) {
                      return a.baseAddress == b.baseAddress &&
                             a.prefixLength == b.prefixLength &&
                             a.interfaceName == b.interfaceName;
                  }),
                  targets.end());

    return targets;
}

QList<ScannerWindow::AdapterInfo> ScannerWindow::buildAdapters() const
{
    QList<AdapterInfo> adapters;
    QHash<QString, QStringList> dnsDomains;
#ifdef Q_OS_LINUX
    QProcess domainQuery;
    domainQuery.start("resolvectl", {"--json=short", "domain"});
    if (domainQuery.waitForStarted(100) && domainQuery.waitForFinished(500) &&
        domainQuery.exitStatus() == QProcess::NormalExit &&
        domainQuery.exitCode() == 0) {
        dnsDomains = parseAdapterDnsDomains(domainQuery.readAllStandardOutput());
    } else if (domainQuery.state() != QProcess::NotRunning) {
        domainQuery.kill();
        domainQuery.waitForFinished(100);
    }
#endif
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &iface : interfaces) {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) ||
            !(flags & QNetworkInterface::IsRunning) ||
            (flags & QNetworkInterface::IsLoopBack)) {
            continue;
        }

        QString bestIp;
        bool hasRoutable = false;
        for (const QNetworkAddressEntry &entry : iface.addressEntries()) {
            const QHostAddress ip = entry.ip();
            if (ip.protocol() != QAbstractSocket::IPv4Protocol || ip.isNull() || ip.isLoopback() || ip.isMulticast()) {
                continue;
            }
            const quint32 value = ipv4ToInt(ip);
            const bool linkLocal = isLinkLocalIpv4(value);
            if (bestIp.isEmpty() || (!linkLocal && !hasRoutable)) {
                bestIp = ip.toString();
            }
            if (!linkLocal) {
                hasRoutable = true;
            }
        }
        if (bestIp.isEmpty()) {
            continue;
        }

        AdapterInfo adapter;
        adapter.interfaceName = iface.name();
        adapter.interfaceLabel = iface.humanReadableName();
        adapter.localIp = bestIp;
        adapter.localMac = iface.hardwareAddress().toUpper();
        adapter.dnsSuffixes = dnsDomains.value(adapter.interfaceName);
        adapter.isPhysical = !isLikelyVirtualInterface(iface);
        adapter.isRoutable = hasRoutable;
        adapter.hasDefaultRoute = hasDefaultRoute(adapter.interfaceName);
        adapters.append(adapter);
    }

    auto rank = [](const AdapterInfo &adapter) {
        if (adapter.isPhysical && adapter.isRoutable && adapter.hasDefaultRoute) return 0;
        if (adapter.isPhysical && adapter.isRoutable) return 1;
        if (adapter.isPhysical) return 2;
        if (adapter.isRoutable) return 3;
        return 4;
    };
    std::sort(adapters.begin(), adapters.end(), [&](const AdapterInfo &a, const AdapterInfo &b) {
        const int ra = rank(a);
        const int rb = rank(b);
        if (ra != rb) {
            return ra < rb;
        }
        if (a.interfaceLabel != b.interfaceLabel) {
            return a.interfaceLabel < b.interfaceLabel;
        }
        return a.localIp < b.localIp;
    });

    return adapters;
}

QHash<QString, QStringList> ScannerWindow::parseAdapterDnsDomains(
    const QByteArray &json)
{
    QHash<QString, QStringList> domains;
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(json, &error);
    if (error.error != QJsonParseError::NoError || !document.isArray()) {
        return domains;
    }
    for (const QJsonValue &value : document.array()) {
        const QJsonObject link = value.toObject();
        const QString interfaceName = link.value("ifname").toString().trimmed();
        if (interfaceName.isEmpty()) {
            continue;
        }
        QStringList suffixes;
        for (const QJsonValue &domainValue : link.value("searchDomains").toArray()) {
            const QJsonObject domain = domainValue.toObject();
            if (domain.value("routeOnly").toBool()) {
                continue;
            }
            QString suffix = domain.value("name").toString().trimmed();
            while (suffix.startsWith('.')) {
                suffix.remove(0, 1);
            }
            while (suffix.endsWith('.')) {
                suffix.chop(1);
            }
            if (!normalizedHostnameKey(suffix).isEmpty() &&
                !suffixes.contains(suffix, Qt::CaseInsensitive)) {
                suffixes.append(suffix);
            }
        }
        if (!suffixes.isEmpty()) {
            domains.insert(interfaceName, suffixes);
        }
    }
    return domains;
}

DefaultTargetPlan ScannerWindow::buildDefaultTargetPlanForNetworks(
    const QList<NetworkTarget> &targets) const
{
    QList<DefaultNetworkInput> inputs;
    QSet<QString> includedInterfaces;
    const auto appendInterface = [&](const QString &interfaceName) {
        for (const NetworkTarget &target : targets) {
            if (target.interfaceName != interfaceName) {
                continue;
            }
            inputs.append({ipv4ToInt(QHostAddress(target.localIp)),
                           target.prefixLength,
                           target.interfaceName,
                           target.interfaceLabel});
        }
        includedInterfaces.insert(interfaceName);
    };
    for (const AdapterInfo &adapter : adapters_) {
        appendInterface(adapter.interfaceName);
    }
    for (const NetworkTarget &target : targets) {
        if (!includedInterfaces.contains(target.interfaceName)) {
            appendInterface(target.interfaceName);
        }
    }
    return ::buildDefaultTargetPlan(
        inputs, kMaxHostsToScan, 2048, targetTextFormat_);
}

DefaultTargetPlan ScannerWindow::buildDefaultTargetPlanForAdapter(
    const QString &interfaceName) const
{
    QList<NetworkTarget> targets;
    for (const NetworkTarget &target : networkTargets_) {
        if (target.interfaceName == interfaceName) {
            targets.append(target);
        }
    }
    return buildDefaultTargetPlanForNetworks(targets);
}

int ScannerWindow::preferredAdapterIndex() const
{
    if (adapters_.isEmpty()) {
        return -1;
    }
    return 0;
}

int ScannerWindow::resolveAdapterIndexForTargets(const QList<QHostAddress> &hosts) const
{
    if (adapters_.isEmpty()) {
        return -1;
    }
    QHash<QString, int> matchesByIface;
    for (const QHostAddress &host : hosts) {
        const quint32 hostIp = ipv4ToInt(host);
        for (const NetworkTarget &target : networkTargets_) {
            const quint32 base = ipv4ToInt(target.baseAddress);
            const quint32 mask = target.prefixLength == 0 ? 0 : (0xFFFFFFFFu << (32 - target.prefixLength));
            if ((hostIp & mask) == (base & mask)) {
                matchesByIface[target.interfaceName] += 1;
            }
        }
    }

    int bestIndex = -1;
    int bestScore = -1;
    for (int i = 0; i < adapters_.size(); ++i) {
        const int score = matchesByIface.value(adapters_[i].interfaceName, 0);
        if (score > bestScore) {
            bestScore = score;
            bestIndex = i;
        }
    }
    if (bestScore <= 0) {
        return preferredAdapterIndex();
    }
    return bestIndex;
}

void ScannerWindow::refreshAdapters()
{
    QString previousAdapter;
    const int previousIndex = adapterCombo_->currentData().toInt();
    if (previousIndex >= 0 && previousIndex < adapters_.size()) {
        previousAdapter = adapters_[previousIndex].interfaceName;
    }

    networkTargets_ = detectDefaultNetworks();
    adapters_ = buildAdapters();
    const int preferred = preferredAdapterIndex();
    const DefaultTargetPlan defaultPlan =
        preferred >= 0 ? buildDefaultTargetPlanForAdapter(adapters_[preferred].interfaceName)
                       : DefaultTargetPlan{};
    defaultTargetText_ = defaultPlan.targetText;
    QStringList defaultNotices;
    if (!defaultPlan.omittedInterfaces.isEmpty()) {
        defaultNotices.append(
            QString("Auto targets were bounded by the host or input limit; omitted some "
                    "addresses from: %1.")
                .arg(defaultPlan.omittedInterfaces.join(", ")));
    }
    if (preferred >= 0 && adapters_.size() > 1) {
        const AdapterInfo &adapter = adapters_[preferred];
        defaultNotices.append(
            QString("Auto targets use %1 [%2] so every probe stays on one adapter; select "
                    "another adapter to target its network.")
                .arg(adapter.interfaceLabel, adapter.localIp));
    }
    defaultTargetNotice_ = defaultNotices.join(' ');

    adapterCombo_->clear();
    adapterCombo_->addItem("Auto Select", -1);
    for (int i = 0; i < adapters_.size(); ++i) {
        const AdapterInfo &adapter = adapters_[i];
        const QString label = QString("%1 [%2]").arg(adapter.interfaceLabel, adapter.localIp);
        adapterCombo_->addItem(label, i);
    }

    bool restoredPrevious = false;
    if (previousAdapter.isEmpty() && previousIndex == -1) {
        const int preferred = preferredAdapterIndex();
        adapterCombo_->setCurrentIndex((preferred >= 0) ? (preferred + 1) : 0);
        restoredPrevious = true;
    } else if (!previousAdapter.isEmpty()) {
        for (int i = 0; i < adapters_.size(); ++i) {
            if (adapters_[i].interfaceName == previousAdapter) {
                adapterCombo_->setCurrentIndex(i + 1);
                restoredPrevious = true;
                break;
            }
        }
    }
    if (!restoredPrevious) {
        const int preferred = preferredAdapterIndex();
        adapterCombo_->setCurrentIndex((preferred >= 0) ? (preferred + 1) : 0);
    }

    if (targetInput_->text().trimmed().isEmpty() || !userCustomizedTargets_) {
        applyDefaultTargets();
    }

    const bool hasNetwork = !adapters_.isEmpty();
    if (!scanWatcher_.isRunning()) {
        scanButton_->setEnabled(hasNetwork ||
                                isDebugScanFixtureTarget(targetInput_->text()));
    }
    defaultsButton_->setEnabled(hasNetwork);

    if (!hasNetwork) {
        showStatusMessage("No connected routable IPv4 adapter detected.");
    } else if (!appliedDefaultTargetNotice_.isEmpty()) {
        showStatusMessage(appliedDefaultTargetNotice_);
    } else {
        showStatusMessage("Ready.");
    }
}

void ScannerWindow::closeEvent(QCloseEvent *event)
{
    if (scanWatcher_.isRunning()) {
        closePending_ = true;
        if (cancelRequested_) {
            cancelRequested_->store(true);
        }
        showStatusMessage("Stopping scan before closing...");
        scanButton_->setEnabled(false);
        event->ignore();
        return;
    }
    saveSettings();
    QMainWindow::closeEvent(event);
}

void ScannerWindow::applyDefaultTargets()
{
    const int selected = adapterCombo_->currentData().toInt();
    appliedDefaultTargetNotice_.clear();
    if (selected == -1) {
        targetInput_->setText(defaultTargetText_);
        appliedDefaultTargetNotice_ = defaultTargetNotice_;
    } else if (selected >= 0 && selected < adapters_.size()) {
        const DefaultTargetPlan adapterPlan =
            buildDefaultTargetPlanForAdapter(adapters_[selected].interfaceName);
        if (!adapterPlan.targetText.isEmpty()) {
            targetInput_->setText(adapterPlan.targetText);
        } else {
            targetInput_->setText(
                targetTextFormat_ == TargetTextFormat::Cidr
                    ? QString("%1/32").arg(adapters_[selected].localIp)
                    : adapters_[selected].localIp);
        }
        if (!adapterPlan.omittedInterfaces.isEmpty()) {
            appliedDefaultTargetNotice_ =
                QString("Auto targets were bounded by the host or input limit; omitted some "
                        "addresses from: %1.")
                    .arg(adapterPlan.omittedInterfaces.join(", "));
        }
    } else {
        targetInput_->setText(defaultTargetText_);
        appliedDefaultTargetNotice_ = defaultTargetNotice_;
    }
    userCustomizedTargets_ = false;
    validateTargetLimitFeedback(targetInput_->text());
    if (!appliedDefaultTargetNotice_.isEmpty()) {
        showStatusMessage(appliedDefaultTargetNotice_);
    }
}

void ScannerWindow::startScan()
{
    if (scanCompletionPending_) {
        return;
    }
    if (scanWatcher_.isRunning()) {
        if (cancelRequested_) {
            cancelRequested_->store(true);
            showStatusMessage("Stopping scan...");
        }
        return;
    }

    const QString rawTargetText = targetInput_->text();
    const QString targetText = rawTargetText.trimmed();
    if (!isSafeTextInput(targetText, 2048)) {
        showStatusMessage("Invalid target input.");
        return;
    }
    if (isDebugScanFixtureTarget(rawTargetText)) {
        startDebugScan();
        return;
    }

    QString parseError;
    const QList<QHostAddress> hosts = parseTargetsInput(targetText, &parseError);
    if (!parseError.isEmpty()) {
        showStatusMessage(parseError);
        return;
    }

    if (hosts.isEmpty()) {
        showStatusMessage("No scan targets resolved.");
        return;
    }
    const int selectedAdapterData = adapterCombo_->currentData().toInt();
    int adapterIdx = selectedAdapterData;
    if (selectedAdapterData == -1) {
        adapterIdx = resolveAdapterIndexForTargets(hosts);
        if (adapterIdx < 0) {
            showStatusMessage("No suitable adapter found for selected targets.");
            return;
        }
    }
    if (adapterIdx < 0 || adapterIdx >= adapters_.size()) {
        showStatusMessage("Select a valid adapter.");
        return;
    }
    const AdapterInfo adapter = adapters_[adapterIdx];
    QHostAddress bindAddress;
    if (!bindAddress.setAddress(adapter.localIp) || bindAddress.protocol() != QAbstractSocket::IPv4Protocol) {
        showStatusMessage(QString("Adapter binding failed: '%1' has invalid local IPv4 (%2).")
                              .arg(adapter.interfaceLabel, adapter.localIp));
        return;
    }
    {
        QTcpSocket bindProbe;
        if (!bindProbe.bind(bindAddress, 0)) {
            showStatusMessage(QString("Adapter binding failed on '%1' (%2).")
                                  .arg(adapter.interfaceLabel, adapter.localIp));
            return;
        }
        bindProbe.abort();
    }

    const ScanOptions scanOptions = captureScanOptions(adapter);
    if (!confirmScanAuthorization(scanOptions)) {
        showStatusMessage("Scan canceled before launch.");
        return;
    }
    const bool targetRetained = recordTargetHistory(targetText);
    const qint64 estimatedMs = estimatedScanUpperBoundMs(
        hosts.size(), scanOptions.maxParallelProbes, scanOptions.targetDeadlineMs);
    const qint64 estimatedSeconds = (estimatedMs + 999) / 1000;
    const QString estimateText = estimatedSeconds >= 60
                                     ? QString("%1m %2s")
                                           .arg(estimatedSeconds / 60)
                                           .arg(estimatedSeconds % 60)
                                     : QString("%1s").arg(estimatedSeconds);
    if (estimatedMs > 10 * 60 * 1000 &&
        QMessageBox::question(
            this,
            "Large Scan Estimate",
            QString("Based on %1 targets, %2 workers, and the selected per-target timeout, "
                    "this scan could take up to about %3 in the worst case. Continue?")
                .arg(hosts.size())
                .arg(scanOptions.maxParallelProbes)
                .arg(estimateText),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes) {
        showStatusMessage("Scan canceled before launch.");
        return;
    }

    pendingDisplayResults_.clear();
    resultFlushTimer_->stop();
    scanCompletionPending_ = false;
    resultModel_->clear();

    scanInProgress_ = true;
    activeScanOptions_ = scanOptions;
    hasActiveScanOptions_ = true;
    activeScanTargetRetained_ = targetRetained;
    updateProbeSummary();
    scanButton_->setToolTip("Stop scan");
    applyToolbarDisplayMode();
    refreshAdaptersButton_->setEnabled(false);
    defaultsButton_->setEnabled(false);
    adapterCombo_->setEnabled(false);
    targetInput_->setEnabled(false);

    showStatusMessage(QString("Scanning %1 host(s) via %2...")
                          .arg(hosts.size())
                          .arg(adapter.interfaceLabel));
    statusProgressBar_->setRange(0, hosts.size());
    statusProgressBar_->setValue(0);
    statusProgressBar_->setVisible(true);

    cancelRequested_ = std::make_shared<std::atomic_bool>(false);
    const std::shared_ptr<std::atomic_bool> scanCancellation = cancelRequested_;

    QFuture<QList<ScanResult>> future = QtConcurrent::run([this, scanOptions, hosts, scanCancellation]() {
        const auto onProgress = [this, scanCancellation](int current, int total) {
            if (cancellable::isCancelled(scanCancellation)) {
                return;
            }
            QMetaObject::invokeMethod(this, [this, current, total, scanCancellation]() {
                if (cancellable::isCancelled(scanCancellation)) {
                    return;
                }
                updateProgress(current, total);
            }, Qt::QueuedConnection);
        };

        const auto onResult = [this, scanCancellation](const ScanResult &result) {
            if (cancellable::isCancelled(scanCancellation)) {
                return;
            }
            QMetaObject::invokeMethod(this, [this, result, scanCancellation]() {
                if (cancellable::isCancelled(scanCancellation) ||
                    scanCompletionPending_ || !scanInProgress_) {
                    return;
                }
                queueResultForDisplay(result);
            }, Qt::QueuedConnection);
        };

        return scanHosts(scanOptions, hosts, scanCancellation, onProgress, onResult);
    });
    scanWatcher_.setFuture(future);
}

void ScannerWindow::startDebugScan()
{
    pendingDisplayResults_.clear();
    resultFlushTimer_->stop();
    scanCompletionPending_ = false;
    resultModel_->clear();

    scanInProgress_ = true;
    scanButton_->setToolTip("Stop scan");
    applyToolbarDisplayMode();
    refreshAdaptersButton_->setEnabled(false);
    defaultsButton_->setEnabled(false);
    adapterCombo_->setEnabled(false);
    targetInput_->setEnabled(false);

    const int total = debugScanFixtureResultCount();
    showStatusMessage(QString("Running hidden test fixture (%1 devices)...").arg(total));
    statusProgressBar_->setRange(0, total);
    statusProgressBar_->setValue(0);
    statusProgressBar_->setVisible(true);

    cancelRequested_ = std::make_shared<std::atomic_bool>(false);
    const std::shared_ptr<std::atomic_bool> scanCancellation = cancelRequested_;
    const int fixtureAccuracy = std::clamp(accuracyLevel_, 0, 3);
    QFuture<QList<ScanResult>> future = QtConcurrent::run(
        [this, fixtureAccuracy, scanCancellation]() {
            const auto onProgress = [this, scanCancellation](int current, int progressTotal) {
                if (cancellable::isCancelled(scanCancellation)) {
                    return;
                }
                QMetaObject::invokeMethod(
                    this, [this, current, progressTotal, scanCancellation]() {
                        if (!cancellable::isCancelled(scanCancellation)) {
                            updateProgress(current, progressTotal);
                        }
                    }, Qt::QueuedConnection);
            };
            const auto onResult = [this, scanCancellation](const ScanResult &result) {
                if (cancellable::isCancelled(scanCancellation)) {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, result, scanCancellation]() {
                    if (!cancellable::isCancelled(scanCancellation) &&
                        !scanCompletionPending_ && scanInProgress_) {
                        queueResultForDisplay(result);
                    }
                }, Qt::QueuedConnection);
            };
            return runDebugScan(fixtureAccuracy, scanCancellation, onProgress, onResult);
        });
    scanWatcher_.setFuture(future);
}

QList<ScanResult> ScannerWindow::runDebugScan(
    int accuracyLevel,
    const std::shared_ptr<std::atomic_bool> &cancelRequested,
    const std::function<void(int, int)> &onProgress,
    const std::function<void(const ScanResult &)> &onResult) const
{
    QList<ScanResult> results;
    const int total = debugScanFixtureResultCount();
    results.reserve(total);
    const int intervalMs = debugScanFixtureIntervalMs(accuracyLevel);
    for (int index = 0; index < total; ++index) {
        if (cancellable::isCancelled(cancelRequested) ||
            cancellable::waitForDelay(intervalMs, cancelRequested) !=
                cancellable::WaitResult::Completed) {
            break;
        }
        const ScanResult result = debugScanFixtureResult(index);
        results.append(result);
        if (onResult) {
            onResult(result);
        }
        if (onProgress) {
            onProgress(index + 1, total);
        }
    }
    return results;
}

QList<QHostAddress> ScannerWindow::parseTargetsInput(const QString &text, QString *error) const
{
    const TargetParseResult result = TargetParser::parse(text, kMaxHostsToScan);
    if (error != nullptr) {
        *error = result.error;
    }
    return result.hosts;
}

QList<ScanResult> ScannerWindow::scanHosts(const ScanOptions &options,
                                           const QList<QHostAddress> &hosts,
                                           const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                           const std::function<void(int, int)> &onProgress,
                                           const std::function<void(const ScanResult &)> &onResult) const
{
    // Shared, thread-safe accumulator for progressive per-host updates.
    QList<ScanResult> results;
    QMutex resultsMutex;
    const auto publishResult = [&](const ScanResult &result) {
        if (cancellable::isCancelled(cancelRequested)) {
            return;
        }
        // Merge data by interface plus IP so overlapping links retain distinct identities.
        bool shouldEmit = false;
        ScanResult emitResult = result;
        {
            QMutexLocker locker(&resultsMutex);
            auto it = std::find_if(results.begin(), results.end(), [&](const ScanResult &existing) {
                return existing.ip == result.ip &&
                       existing.interfaceName == result.interfaceName;
            });

            if (it == results.end()) {
                results.append(result);
                shouldEmit = true;
            } else {
                if (it->mac == "Unknown" && result.mac != "Unknown") {
                    it->mac = result.mac;
                    shouldEmit = true;
                }
                if (it->vendor == "Unknown" && result.vendor != "Unknown") {
                    it->vendor = result.vendor;
                    shouldEmit = true;
                }
                const HostnameEvidence currentHostname{
                    it->hostname, it->hostnameSource};
                for (const HostnameEvidence &candidate : result.hostnameEvidence) {
                    it->hostnameEvidence = mergeHostnameEvidence(
                        it->hostnameEvidence, candidate);
                }
                const HostnameEvidence mergedHostname = preferredHostname(
                    it->hostnameEvidence);
                if (mergedHostname.hostname != currentHostname.hostname ||
                    mergedHostname.source != currentHostname.source) {
                    it->hostname = mergedHostname.hostname;
                    it->hostnameSource = mergedHostname.source;
                    shouldEmit = true;
                }
                for (const ResolverEvent &event : result.resolverEvents) {
                    const QList<ResolverEvent> mergedEvents = mergeResolverEvents(
                        it->resolverEvents, event);
                    if (mergedEvents.size() != it->resolverEvents.size()) {
                        it->resolverEvents = mergedEvents;
                        shouldEmit = true;
                    }
                }
                if (it->services.isEmpty() && !result.services.isEmpty()) {
                    it->services = result.services;
                    shouldEmit = true;
                }
                emitResult = *it;
            }
        }

        if (shouldEmit && onResult) {
            onResult(emitResult);
        }
    };

    const QString gatewayIp = lookupGatewayIp(options.interfaceName);
    const int interfaceIndex = QNetworkInterface::interfaceIndexFromName(
        options.interfaceName);
    auto mdnsResolver = std::make_shared<ScanMdnsResolver>(
        interfaceIndex, cancelRequested, createAvahiDbusBackend());

    const int total = hosts.size();
    std::atomic<int> nextIndex{0};
    std::atomic<int> scannedCount{0};

    QThreadPool pool;
    const int requestedWorkers = std::clamp(options.maxParallelProbes, 1, kMaxParallelProbes);
    const int workerCount = requestedWorkers;
    pool.setMaxThreadCount(workerCount);

    QList<QFuture<void>> workers;
    workers.reserve(workerCount);

    for (int worker = 0; worker < workerCount; ++worker) {
        // Worker threads pull host indices atomically to avoid overlap.
        workers.append(QtConcurrent::run(&pool, [&, gatewayIp, cancelRequested]() {
            while (true) {
                if (cancelRequested && cancelRequested->load()) {
                    break;
                }

                const int index = nextIndex.fetch_add(1);
                if (index >= total) {
                    break;
                }

                const QHostAddress host = hosts[index];
                const QString ipString = host.toString();
                const TargetBudget budget(options.targetDeadlineMs);

                bool alive = false;
                QString discoveredMac;
                NeighborObservation neighbor;
                QList<ServiceHit> discoveredServices;
                bool servicesProbed = false;
                if (ipString == options.localIp) {
                    alive = true;
                    discoveredMac = options.localMac;
                } else if (ipString == gatewayIp) {
                    alive = true;
                } else {
                    alive = pingHost(host, options, budget, cancelRequested);
                    if (shouldProbeServicesForDiscovery(
                            alive, options.enabledServiceIds.size()) && !budget.expired()) {
                        servicesProbed = true;
                        discoveredServices = probeServices(
                            ipString, options.localIp, budget, cancelRequested, options);
                        alive = !discoveredServices.isEmpty();
                    }
                    if (!alive) {
                        neighbor = lookupNeighbor(
                            ipString, options.interfaceName, budget, cancelRequested);
                        neighbor = confirmNeighborLiveness(neighbor,
                                                          ipString,
                                                          options.interfaceName,
                                                          options,
                                                          budget,
                                                          cancelRequested);
                        if (neighbor.suppliesMacMetadata()) {
                            discoveredMac = neighbor.mac;
                        }
                        if (neighbor.establishesLiveness()) {
                            alive = true;
                        }
                    }
                }

                if (alive) {
                    ScanResult result;
                    result.ip = ipString;
                    result.interfaceName = options.interfaceName;
                    for (const AliveHostStage stage : kAliveHostStageOrder) {
                        switch (stage) {
                        case AliveHostStage::Services:
                            result.services = servicesProbed
                                                  ? discoveredServices
                                                  : probeServices(ipString,
                                                                  options.localIp,
                                                                  budget,
                                                                  cancelRequested,
                                                                  options);
                            break;
                        case AliveHostStage::MacAddress:
                            if (discoveredMac.isEmpty()) {
                                if (neighbor.ip.isEmpty()) {
                                    neighbor = lookupNeighbor(ipString,
                                                              options.interfaceName,
                                                              budget,
                                                              cancelRequested);
                                }
                                if (neighbor.suppliesMacMetadata()) {
                                    discoveredMac = neighbor.mac;
                                }
                            }
                            result.mac = discoveredMac;
                            break;
                        case AliveHostStage::Vendor:
                            result.vendor = lookupVendor(result.mac, options);
                            break;
                        case AliveHostStage::Hostname: {
                            HostnameEvidence preliminary;
                            if (ipString == options.localIp) {
                                preliminary.hostname = qualifyHostname(
                                    QHostInfo::localHostName(),
                                    options.dnsSuffixes.value(0));
                                preliminary.source = HostnameSource::LocalHost;
                            }
                            const HostnameResolution resolved = lookupHostname(
                                ipString,
                                preliminary,
                                options.dnsSuffixes,
                                options.accuracyLevel,
                                budget,
                                cancelRequested,
                                *mdnsResolver);
                            result.hostnameEvidence = resolved.evidence;
                            result.resolverEvents = resolved.resolverEvents;
                            const HostnameEvidence preferred = preferredHostname(
                                result.hostnameEvidence);
                            result.hostname = preferred.hostname;
                            result.hostnameSource = preferred.source;
                            break;
                        }
                        case AliveHostStage::NormalizeIdentity:
                            if (result.mac.isEmpty()) {
                                result.mac = "Unknown";
                            }
                            if (result.vendor.isEmpty()) {
                                result.vendor = "Unknown";
                            }
                            if (result.hostname.isEmpty()) {
                                result.hostname = "Unknown";
                            }
                            break;
                        case AliveHostStage::Details:
                            result.detailsText = collectDeviceDetails(result, options);
                            break;
                        }
                    }
                    publishResult(result);
                }

                const int current = scannedCount.fetch_add(1) + 1;
                if (onProgress) {
                    onProgress(current, total);
                }

                if (cancelRequested && cancelRequested->load()) {
                    break;
                }
            }
        }));
    }

    for (QFuture<void> &worker : workers) {
        worker.waitForFinished();
    }

    std::sort(results.begin(), results.end(), [](const ScanResult &a, const ScanResult &b) {
        return ipv4ToInt(QHostAddress(a.ip)) < ipv4ToInt(QHostAddress(b.ip));
    });

    return results;
}

bool ScannerWindow::pingHost(const QHostAddress &address,
                             const ScanOptions &options,
                             const TargetBudget &budget,
                             const std::shared_ptr<std::atomic_bool> &cancelRequested) const
{
#ifdef Q_OS_LINUX
    const QString pingProgram = !QStandardPaths::findExecutable("ping").isEmpty()
                                    ? QStandardPaths::findExecutable("ping")
                                    : QString("ping");
    const auto runPing = [&](const QStringList &baseArgs) {
        for (int attempt = 0; attempt < options.pingAttempts; ++attempt) {
            if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
                return false;
            }
            QProcess ping;
            const int timeoutSeconds = options.pingTimeoutSeconds;
            QStringList args = {"-n", "-c", "1", "-W", QString::number(timeoutSeconds)};
            args.append(baseArgs);
            args << address.toString();
            ping.start(pingProgram, args);

            const int waitMs = budget.clampTimeout(
                pingAttemptWaitMs(timeoutSeconds), kProcessCleanupReserveMs);
            if (cancellable::waitForProcess(
                    ping,
                    waitMs,
                    cancelRequested,
                    [&budget]() { return budget.remainingMs(); }) !=
                cancellable::WaitResult::Completed) {
                continue;
            }

            if (ping.exitStatus() == QProcess::NormalExit && ping.exitCode() == 0) {
                return true;
            }
        }
        return false;
    };

    if (!options.interfaceName.isEmpty()) {
        return runPing({"-I", options.interfaceName});
    }
    return runPing({});
#else
    Q_UNUSED(address)
    Q_UNUSED(options)
    Q_UNUSED(budget)
    Q_UNUSED(cancelRequested)
    return false;
#endif
}

NeighborObservation ScannerWindow::lookupNeighbor(
    const QString &ip,
    const QString &interfaceName,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested) const
{
#ifdef Q_OS_LINUX
    if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
        return {};
    }
    QProcess ipNeigh;
    QStringList args{"-j", "neigh", "show", ip};
    if (!interfaceName.isEmpty()) {
        args << "dev" << interfaceName;
    }
    ipNeigh.start("ip", args);
    if (cancellable::waitForProcess(
            ipNeigh,
            budget.clampTimeout(1000, kProcessCleanupReserveMs),
            cancelRequested,
            [&budget]() { return budget.remainingMs(); }) ==
            cancellable::WaitResult::Completed &&
        ipNeigh.exitStatus() == QProcess::NormalExit && ipNeigh.exitCode() == 0) {
        const QList<NeighborObservation> observations =
            parseLinuxNeighborJson(ipNeigh.readAllStandardOutput(), interfaceName);
        const QString expectedKey = neighborIdentityKey(interfaceName, ip);
        for (const NeighborObservation &observation : observations) {
            if (interfaceName.isEmpty() ? observation.ip == ip
                                        : observation.identityKey() == expectedKey) {
                return observation;
            }
        }
    }
#else
    Q_UNUSED(ip)
    Q_UNUSED(interfaceName)
    Q_UNUSED(budget)
    Q_UNUSED(cancelRequested)
#endif
    return {};
}

NeighborObservation ScannerWindow::confirmNeighborLiveness(
    const NeighborObservation &initial,
    const QString &ip,
    const QString &interfaceName,
    const ScanOptions &options,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested) const
{
    NeighborObservation latest = initial;
    if (!latest.suppliesMacMetadata() || latest.establishesLiveness() ||
        options.neighborConfirmationMs <= 0 || budget.expired()) {
        return latest;
    }

    QElapsedTimer confirmation;
    confirmation.start();
    while (confirmation.elapsed() < options.neighborConfirmationMs && !budget.expired()) {
        const int confirmationRemaining = options.neighborConfirmationMs -
                                          static_cast<int>(confirmation.elapsed());
        const int waitMs = std::min({250, confirmationRemaining, budget.remainingMs()});
        if (waitMs <= 0 ||
            cancellable::waitForDelay(waitMs, cancelRequested) !=
                cancellable::WaitResult::Completed) {
            break;
        }
        const NeighborObservation candidate =
            lookupNeighbor(ip, interfaceName, budget, cancelRequested);
        if (candidate.suppliesMacMetadata()) {
            latest = candidate;
        }
        if (candidate.establishesLiveness()) {
            return candidate;
        }
    }
    return latest;
}

QString ScannerWindow::lookupVendor(const QString &mac, const ScanOptions &options) const
{
    return OuiDatabase::lookup(
        mac, options.customOuiVendors, options.builtInOuiVendors);
}

ScannerWindow::HostnameResolution ScannerWindow::lookupHostname(
    const QString &ip,
    const HostnameEvidence &preliminary,
    const QStringList &adapterDnsSuffixes,
    int accuracyLevel,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested,
    ScanMdnsResolver &mdnsResolver) const
{
    HostnameResolution resolution;
    resolution.evidence = mergeHostnameEvidence(resolution.evidence, preliminary);
    const HostnameTimeoutProfile timeouts = hostnameTimeoutProfile(accuracyLevel);
    const auto addEvent = [&resolution](ResolverKind resolver,
                                        ResolverOutcome outcome) {
        resolution.resolverEvents = mergeResolverEvents(
            resolution.resolverEvents, {resolver, outcome});
    };

    const cancellable::DnsPtrLookupResult ptr = cancellable::lookupPtr(
        ip, budget.clampTimeout(timeouts.ptrMs), cancelRequested);
    if (ptr.waitResult == cancellable::WaitResult::Cancelled) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::Cancelled);
        return resolution;
    }
    if (ptr.waitResult == cancellable::WaitResult::TimedOut ||
        cancellable::isDnsLookupTimeoutError(ptr.error)) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::TimedOut);
    } else if (ptr.error == QDnsLookup::NoError && !ptr.hostnames.isEmpty()) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::Resolved);
        const QString hostname = preferredPtrHostname(
            ptr.hostnames, adapterDnsSuffixes);
        if (!hostname.isEmpty()) {
            resolution.evidence = mergeHostnameEvidence(
                resolution.evidence, {hostname, HostnameSource::DnsPtr});
        }
    } else if (ptr.error == QDnsLookup::NotFoundError ||
               (ptr.error == QDnsLookup::NoError && ptr.hostnames.isEmpty())) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::NoRecord);
    } else if (ptr.error == QDnsLookup::InvalidRequestError ||
               ptr.error == QDnsLookup::InvalidReplyError) {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::InvalidResponse);
    } else {
        addEvent(ResolverKind::DnsPtr, ResolverOutcome::BackendUnavailable);
    }

    if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
        return resolution;
    }
    cancellable::WaitResult lookupResult = cancellable::WaitResult::Failed;
    const QHostInfo info = cancellable::lookupHost(
        ip, budget.clampTimeout(timeouts.systemMs), cancelRequested, &lookupResult);
    if (lookupResult == cancellable::WaitResult::Cancelled) {
        addEvent(ResolverKind::System, ResolverOutcome::Cancelled);
        return resolution;
    }
    if (lookupResult == cancellable::WaitResult::TimedOut) {
        addEvent(ResolverKind::System, ResolverOutcome::TimedOut);
    } else if (info.error() == QHostInfo::NoError &&
               !normalizedHostnameKey(info.hostName()).isEmpty() &&
               info.hostName() != ip) {
        addEvent(ResolverKind::System, ResolverOutcome::Resolved);
        resolution.evidence = mergeHostnameEvidence(
            resolution.evidence,
            {qualifyHostname(info.hostName(), adapterDnsSuffixes.value(0)),
             HostnameSource::SystemResolver});
    } else if (info.error() == QHostInfo::HostNotFound ||
               (info.error() == QHostInfo::NoError &&
                normalizedHostnameKey(info.hostName()).isEmpty())) {
        addEvent(ResolverKind::System, ResolverOutcome::NoRecord);
    } else {
        addEvent(ResolverKind::System, ResolverOutcome::BackendUnavailable);
    }

    if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
        return resolution;
    }
    const MdnsLookupResult mdns = mdnsResolver.resolve(
        ip, budget.clampTimeout(timeouts.mdnsMs));
    switch (mdns.status) {
    case MdnsLookupStatus::Resolved:
        addEvent(ResolverKind::Mdns, ResolverOutcome::Resolved);
        resolution.evidence = mergeHostnameEvidence(
            resolution.evidence, {mdns.hostname, HostnameSource::AvahiMdns});
        break;
    case MdnsLookupStatus::NoRecord:
        addEvent(ResolverKind::Mdns, ResolverOutcome::NoRecord);
        break;
    case MdnsLookupStatus::TimedOut:
        addEvent(ResolverKind::Mdns, ResolverOutcome::TimedOut);
        break;
    case MdnsLookupStatus::Cancelled:
        addEvent(ResolverKind::Mdns, ResolverOutcome::Cancelled);
        break;
    case MdnsLookupStatus::BackendUnavailable:
        addEvent(ResolverKind::Mdns, ResolverOutcome::BackendUnavailable);
        break;
    case MdnsLookupStatus::DaemonUnavailable:
        addEvent(ResolverKind::Mdns, ResolverOutcome::DaemonUnavailable);
        break;
    case MdnsLookupStatus::MulticastUnavailable:
        addEvent(ResolverKind::Mdns, ResolverOutcome::MulticastUnavailable);
        break;
    case MdnsLookupStatus::InvalidResponse:
        addEvent(ResolverKind::Mdns, ResolverOutcome::InvalidResponse);
        break;
    }
    return resolution;
}

QString ScannerWindow::lookupGatewayIp(const QString &interfaceName) const
{
#ifdef Q_OS_LINUX
    QFile routeFile("/proc/net/route");
    if (!routeFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    while (!routeFile.atEnd()) {
        const QString line = QString::fromUtf8(routeFile.readLine()).trimmed();
        if (line.isEmpty() || line.startsWith("Iface")) {
            continue;
        }

        const QStringList fields = line.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        if (fields.size() < 3) {
            continue;
        }

        if (fields[0] == interfaceName && fields[1] == "00000000") {
            return hexGatewayToIp(fields[2]);
        }
    }
#else
    Q_UNUSED(interfaceName)
#endif
    return {};
}

QList<ScannerWindow::ServiceDefinition> ScannerWindow::availableServices() const
{
    return {
        {"http", "HTTP", 80, true, true},
        {"https", "HTTPS", 443, true, true},
        {"ssh", "SSH", 22, true, false},
        {"rdp", "RDP", 3389, true, false},
        {"ftp", "FTP", 21, false, false},
        {"telnet", "Telnet", 23, false, false},
        {"smb", "SMB", 445, false, false},
        {"smtp25", "SMTP", 25, false, false},
        {"smtps465", "SMTPS", 465, false, false},
        {"smtp587", "SMTP-STARTTLS", 587, false, false}
    };
}

QList<ServiceHit> ScannerWindow::probeServices(const QString &ip,
                                               const QString &localBindIp,
                                               const TargetBudget &budget,
                                               const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                               const ScanOptions &options) const
{
    QList<ServiceHit> hits;
    const auto defs = availableServices();

    for (const ServiceDefinition &def : defs) {
        if (!options.enabledServiceIds.contains(def.id)) {
            continue;
        }
        if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
            break;
        }

        ServiceEvidenceLevel evidence = ServiceEvidenceLevel::OpenPort;
        const bool usesTls = def.id == "https" || def.id == "smtps465";
        const bool open = usesTls
                              ? probeTlsService(def,
                                                ip,
                                                localBindIp,
                                                budget,
                                                cancelRequested,
                                                options,
                                                &evidence)
                              : probePlainService(def,
                                                  ip,
                                                  localBindIp,
                                                  budget,
                                                  cancelRequested,
                                                  options,
                                                  &evidence);
        if (open) {
            ServiceHit hit;
            hit.id = def.id;
            hit.label = def.label;
            hit.port = def.port;
            hit.isWeb = def.isWeb;
            hit.evidence = evidence;
            hits.append(hit);
        }
    }

    return hits;
}

QString ScannerWindow::serviceText(const QList<ServiceHit> &services) const
{
    QStringList parts;
    for (const ServiceHit &service : services) {
        parts.append(serviceEvidenceText(service.label, service.port, service.evidence));
    }
    return parts.join(", ");
}

QString ScannerWindow::normalizeMacHex12(const QString &mac)
{
    QString hex = mac.toUpper();
    hex.remove(':');
    hex.remove('-');
    hex.remove('.');
    if (hex.size() != 12) {
        return {};
    }
    for (const QChar ch : hex) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F'))) {
            return {};
        }
    }
    return hex;
}

QString ScannerWindow::formatMacForDisplay(const QString &mac) const
{
    return formatMacForDisplay(mac, macDisplayFormat_);
}

QString ScannerWindow::formatMacForDisplay(const QString &mac, int displayFormat) const
{
    if (mac.isEmpty() || mac == "Unknown") {
        return "Unknown";
    }
    const QString hex = normalizeMacHex12(mac);
    if (hex.isEmpty()) {
        return mac;
    }

    auto pairJoin = [](const QString &input, const QString &sep) {
        QStringList parts;
        for (int i = 0; i < 12; i += 2) {
            parts.append(input.mid(i, 2));
        }
        return parts.join(sep);
    };

    switch (displayFormat) {
    case MacColonLower:
        return pairJoin(hex.toLower(), ":");
    case MacHyphenUpper:
        return pairJoin(hex, "-");
    case MacHyphenLower:
        return pairJoin(hex.toLower(), "-");
    case MacCiscoDot:
        return QString("%1.%2.%3").arg(hex.mid(0, 4), hex.mid(4, 4), hex.mid(8, 4)).toLower();
    case MacPlainUpper:
        return hex;
    case MacPlainLower:
        return hex.toLower();
    case MacColonUpper:
    default:
        return pairJoin(hex, ":");
    }
}

void ScannerWindow::refreshDisplayedMacAddresses()
{
    resultModel_->notifyMacFormatChanged();
    applyTableColumnSizing();
}

bool ScannerWindow::probePlainService(
    const ServiceDefinition &definition,
    const QString &ip,
    const QString &localBindIp,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested,
    const ScanOptions &options,
    ServiceEvidenceLevel *evidence) const
{
    bool sawOpenPort = false;
    for (int attempt = 0; attempt < options.serviceAttempts; ++attempt) {
        if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
            break;
        }
        QTcpSocket socket;
        if (!localBindIp.isEmpty()) {
            QHostAddress bindAddress;
            if (!bindAddress.setAddress(localBindIp) ||
                bindAddress.protocol() != QAbstractSocket::IPv4Protocol ||
                !socket.bind(bindAddress, 0)) {
                return false;
            }
        }
        socket.connectToHost(ip, static_cast<quint16>(definition.port));
        if (cancellable::waitForConnected(
                socket, budget.clampTimeout(options.serviceTimeoutMs), cancelRequested) !=
            cancellable::WaitResult::Completed) {
            continue;
        }
        sawOpenPort = true;

        const bool expectsResponse = definition.id == "http" || definition.id == "ssh" ||
                                     definition.id == "ftp" || definition.id == "smtp25" ||
                                     definition.id == "smtp587";
        if (!expectsResponse) {
            socket.abort();
            return true;
        }
        QByteArray request;
        if (definition.id == "http") {
            request = "HEAD / HTTP/1.0\r\nHost: " + ip.toUtf8() + "\r\n\r\n";
        }
        if (!request.isEmpty()) {
            socket.write(request);
            if (cancellable::waitForBytesWritten(
                    socket,
                    budget.clampTimeout(options.serviceTimeoutMs),
                    cancelRequested) != cancellable::WaitResult::Completed) {
                socket.abort();
                continue;
            }
        }
        QByteArray response = readServiceResponse(
            socket, budget, cancelRequested, options.serviceTimeoutMs);
        bool verified = false;
        if (definition.id == "smtp587") {
            if (responseVerifiesService("smtp25", response)) {
                socket.write("EHLO open-ip-scanner\r\n");
                if (cancellable::waitForBytesWritten(
                        socket,
                        budget.clampTimeout(options.serviceTimeoutMs),
                        cancelRequested) == cancellable::WaitResult::Completed) {
                    response = readServiceResponse(
                        socket, budget, cancelRequested, options.serviceTimeoutMs, true);
                    verified = responseVerifiesService(definition.id, response);
                }
            }
        } else {
            verified = responseVerifiesService(definition.id, response);
        }
        if (verified) {
            *evidence = ServiceEvidenceLevel::VerifiedProtocol;
            socket.abort();
            return true;
        }
        socket.abort();
    }
    return sawOpenPort;
}

bool ScannerWindow::probeTlsService(
    const ServiceDefinition &definition,
    const QString &ip,
    const QString &localBindIp,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested,
    const ScanOptions &options,
    ServiceEvidenceLevel *evidence) const
{
    bool sawOpenPort = false;
    for (int attempt = 0; attempt < options.serviceAttempts; ++attempt) {
        if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
            break;
        }
        QSslSocket socket;
        bool tcpConnected = false;
        QObject::connect(&socket, &QSslSocket::connected, &socket, [&tcpConnected]() {
            tcpConnected = true;
        });
        QObject::connect(&socket,
                         &QSslSocket::sslErrors,
                         &socket,
                         [&socket](const QList<QSslError> &) { socket.ignoreSslErrors(); });
        if (!localBindIp.isEmpty()) {
            QHostAddress bindAddress;
            if (!bindAddress.setAddress(localBindIp) ||
                bindAddress.protocol() != QAbstractSocket::IPv4Protocol ||
                !socket.bind(bindAddress, 0)) {
                return false;
            }
        }
        socket.connectToHostEncrypted(ip, static_cast<quint16>(definition.port));
        const int timeoutMs = budget.clampTimeout(options.serviceTimeoutMs);
        QElapsedTimer elapsed;
        elapsed.start();
        while (!socket.isEncrypted() && elapsed.elapsed() < timeoutMs &&
               !cancellable::isCancelled(cancelRequested) && !budget.expired()) {
            const int remaining = timeoutMs - static_cast<int>(elapsed.elapsed());
            socket.waitForEncrypted(std::min(25, remaining));
            if (socket.state() == QAbstractSocket::UnconnectedState &&
                socket.error() != QAbstractSocket::UnknownSocketError) {
                break;
            }
        }
        sawOpenPort = sawOpenPort || tcpConnected;
        if (socket.isEncrypted()) {
            bool verified = false;
            if (definition.id == "https") {
                socket.write("HEAD / HTTP/1.0\r\nHost: " + ip.toUtf8() + "\r\n\r\n");
                if (cancellable::waitForBytesWritten(
                        socket,
                        budget.clampTimeout(options.serviceTimeoutMs),
                        cancelRequested) == cancellable::WaitResult::Completed) {
                    verified = responseVerifiesService(
                        definition.id,
                        readServiceResponse(
                            socket, budget, cancelRequested, options.serviceTimeoutMs));
                }
            } else if (definition.id == "smtps465") {
                verified = responseVerifiesService(
                    definition.id,
                    readServiceResponse(
                        socket, budget, cancelRequested, options.serviceTimeoutMs));
            }
            if (verified) {
                *evidence = ServiceEvidenceLevel::VerifiedProtocol;
                socket.abort();
                return true;
            }
        }
        socket.abort();
    }
    return sawOpenPort;
}

QByteArray ScannerWindow::readServiceResponse(
    QTcpSocket &socket,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested,
    int timeoutMs,
    bool smtpMultiline) const
{
    constexpr int kMaxResponseBytes = 4096;
    QByteArray response;
    QElapsedTimer elapsed;
    elapsed.start();
    while (response.size() < kMaxResponseBytes && elapsed.elapsed() < timeoutMs &&
           !cancellable::isCancelled(cancelRequested) && !budget.expired()) {
        if (socket.bytesAvailable() > 0) {
            response.append(socket.read(kMaxResponseBytes - response.size()));
            const QList<QByteArray> lines = response.split('\n');
            const bool hasCompleteLine = lines.size() > 1;
            const QByteArray first = hasCompleteLine ? lines.first().trimmed() : QByteArray();
            bool responseComplete = hasCompleteLine && !smtpMultiline;
            if (smtpMultiline && hasCompleteLine) {
                if (!first.startsWith("250-") && !first.startsWith("250 ")) {
                    responseComplete = true;
                } else {
                    for (int lineIndex = 0; lineIndex + 1 < lines.size(); ++lineIndex) {
                        if (lines.at(lineIndex).trimmed().startsWith("250 ")) {
                            responseComplete = true;
                            break;
                        }
                    }
                }
            }
            if (responseComplete) {
                break;
            }
            continue;
        }
        const int remaining = timeoutMs - static_cast<int>(elapsed.elapsed());
        if (cancellable::waitForReadyRead(
                socket,
                budget.clampTimeout(remaining),
                cancelRequested) != cancellable::WaitResult::Completed) {
            if (socket.bytesAvailable() > 0) {
                response.append(socket.read(kMaxResponseBytes - response.size()));
            }
            break;
        }
    }
    return response;
}

QString ScannerWindow::collectDeviceDetails(const ScanResult &result,
                                            const ScanOptions &options) const
{
    const auto escaped = [](const QString &text) { return text.toHtmlEscaped(); };
    QString html = "<table cellspacing='2' cellpadding='2'>";
    html += QString("<tr><td><b>IP:</b></td><td>%1</td><td></td></tr>")
                .arg(escaped(result.ip));

    QList<HostnameDisplayRow> hostnameRows = hostnameDisplayRows(
        result.hostnameEvidence);
    if (hostnameRows.isEmpty() && !normalizedHostnameKey(result.hostname).isEmpty()) {
        hostnameRows.append({result.hostname,
                             {hostnameSourceLabel(result.hostnameSource)},
                             true});
    }
    if (hostnameRows.isEmpty()) {
        html += "<tr><td><b>Hostname(s):</b></td><td>Unknown</td><td></td></tr>";
    } else {
        for (int index = 0; index < hostnameRows.size(); ++index) {
            const HostnameDisplayRow &row = hostnameRows.at(index);
            const QString heading = index == 0 ? "<b>Hostname(s):</b>" : QString();
            const QString sources = row.sourceLabels.isEmpty()
                                        ? QString()
                                        : QString("(%1)").arg(
                                              escaped(row.sourceLabels.join(", ")));
            const QString hostnameWithSources = sources.isEmpty()
                                                    ? escaped(row.hostname)
                                                    : QString("%1 %2").arg(
                                                          escaped(row.hostname), sources);
            html += QString("<tr><td>%1</td><td>%2</td><td></td></tr>")
                        .arg(heading, hostnameWithSources);
        }
    }

    html += QString("<tr><td><b>MAC:</b></td><td>%1</td><td></td></tr>")
                .arg(escaped(formatMacForDisplay(result.mac, options.macDisplayFormat)));
    html += QString("<tr><td><b>Vendor:</b></td><td>%1</td><td></td></tr>")
                .arg(escaped(result.vendor));
    if (result.services.isEmpty()) {
        html += "<tr><td><b>Services:</b></td><td>None</td><td></td></tr>";
    } else {
        for (int index = 0; index < result.services.size(); ++index) {
            const ServiceHit &service = result.services.at(index);
            const QString heading = index == 0 ? "<b>Services:</b>" : QString();
            const QString evidence = service.evidence ==
                                             ServiceEvidenceLevel::VerifiedProtocol
                                         ? "Verified"
                                         : "Open";
            html += QString("<tr><td>%1</td><td>%2</td><td>(%3)</td></tr>")
                        .arg(heading,
                             escaped(serviceEvidenceText(service.label,
                                                         service.port,
                                                         service.evidence)),
                             evidence);
        }
    }
    html += "</table>";
    return html;
}

QString ScannerWindow::preferredTerminalProgram() const
{
    const QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QString envTerminal = env.value("TERMINAL").trimmed();
    if (!envTerminal.isEmpty()) {
        return envTerminal;
    }
    const QString kdeTerminal = env.value("KDE_TERMINAL_APPLICATION").trimmed();
    if (!kdeTerminal.isEmpty()) {
        return kdeTerminal;
    }
    if (!QStandardPaths::findExecutable("konsole").isEmpty()) {
        return "konsole";
    }
    if (!QStandardPaths::findExecutable("x-terminal-emulator").isEmpty()) {
        return "x-terminal-emulator";
    }
    if (!QStandardPaths::findExecutable("gnome-terminal").isEmpty()) {
        return "gnome-terminal";
    }
    return "xterm";
}

bool ScannerWindow::openPreferredTerminal(const QStringList &args, QString *error) const
{
    auto resolvedExecutable = [](const QString &program) {
        if (program.isEmpty()) {
            return QString();
        }
        if (program.contains('/')) {
            QFileInfo fi(program);
            return (fi.exists() && fi.isFile() && fi.isExecutable()) ? fi.absoluteFilePath() : QString();
        }
        return QStandardPaths::findExecutable(program);
    };

    auto tryStart = [&](const QString &program) {
        const QString resolved = resolvedExecutable(program);
        if (resolved.isEmpty()) {
            return false;
        }
        if (QProcess::startDetached(resolved, args)) {
            return true;
        }
        if (error != nullptr) {
            *error = QString("Failed to launch terminal command: %1").arg(program);
        }
        return false;
    };

    const QString preferred = preferredTerminalProgram();
    if (tryStart(preferred)) {
        return true;
    }
    if (preferred != "konsole" && tryStart("konsole")) {
        return true;
    }
    if (preferred != "x-terminal-emulator" && tryStart("x-terminal-emulator")) {
        return true;
    }
    if (error != nullptr && error->isEmpty()) {
        *error = QString("No runnable terminal command found (tried: %1, konsole, x-terminal-emulator).").arg(preferred);
    }
    return false;
}

void ScannerWindow::openService(const QString &ip, const ServiceHit &service)
{
    if (service.isWeb) {
        const QString scheme = (service.id == "https") ? "https" : "http";
        const QUrl url(QString("%1://%2").arg(scheme, ip));
        if (!QDesktopServices::openUrl(url)) {
            const QString message = QString("Failed to open URL: %1").arg(url.toString());
            QMessageBox::warning(this, "Open Service", message);
            showStatusMessage(message);
        }
        return;
    }

    QString command = customCommands_.value(service.id);
    if (command.trimmed().isEmpty()) {
        QMessageBox::information(this,
                                 "Open Service",
                                 QString("No command configured for %1. Set it in Settings > Preferences.")
                                     .arg(service.label));
        return;
    }

    command.replace("{host}", ip);
    command.replace("{port}", QString::number(service.port));
    command.replace("{url}", QString("%1://%2:%3").arg(service.id, ip).arg(service.port));
    if (!isSafeTextInput(command, 512)) {
        QMessageBox::warning(this, "Open Service", "Configured command contains invalid characters.");
        return;
    }

    const QStringList parts = QProcess::splitCommand(command);
    if (parts.isEmpty()) {
        QMessageBox::warning(this, "Open Service", "Configured command is empty.");
        return;
    }

    const QString programToken = parts.first();
    const QStringList args = parts.mid(1);
    QString resolvedProgram;
    if (programToken.contains('/')) {
        QFileInfo fi(programToken);
        if (fi.exists() && fi.isFile() && fi.isExecutable()) {
            resolvedProgram = fi.absoluteFilePath();
        }
    } else {
        resolvedProgram = QStandardPaths::findExecutable(programToken);
    }

    if (resolvedProgram.isEmpty()) {
        const QString message = QString(
            "Cannot start service command.\nMissing executable: %1\nCommand: %2")
                                    .arg(programToken, command);
        QMessageBox::warning(this, "Open Service", message);
        showStatusMessage(QString("Service launch failed: missing executable '%1'.").arg(programToken));
        return;
    }

    if (!QProcess::startDetached(resolvedProgram, args)) {
        const QString message = QString("Failed to run command:\n%1\nResolved executable: %2")
                                    .arg(command, resolvedProgram);
        QMessageBox::warning(this, "Open Service", message);
        showStatusMessage(QString("Service launch failed: %1").arg(command));
    }
}

void ScannerWindow::finishScan()
{
    const bool wasCanceled = cancelRequested_ && cancelRequested_->load();
    const QList<ScanResult> finalResults = scanWatcher_.result();
    if (closePending_) {
        scanInProgress_ = false;
        cancelRequested_.reset();
        closePending_ = false;
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }
    beginScanCompletionPresentation(finalResults, wasCanceled);
}

void ScannerWindow::beginScanCompletionPresentation(
    const QList<ScanResult> &finalResults,
    bool wasCanceled)
{
    pendingDisplayResults_.clear();
    resultFlushTimer_->stop();
    pendingDisplayResults_ = finalResults;
    completedScanWasCanceled_ = wasCanceled;
    scanCompletionPending_ = true;
    scanButton_->setEnabled(false);
    scanButton_->setToolTip("Finalizing results");
    if (pendingDisplayResults_.isEmpty()) {
        completeScanPresentation();
    } else {
        resultFlushTimer_->start(0);
    }
}

void ScannerWindow::completeScanPresentation()
{
    scanCompletionPending_ = false;
    scanInProgress_ = false;
    hasActiveScanOptions_ = false;
    activeScanTargetRetained_ = false;
    updateProbeSummary();
    scanButton_->setToolTip("Start scan");
    applyToolbarDisplayMode();
    scanButton_->setEnabled(!adapters_.isEmpty() ||
                            isDebugScanFixtureTarget(targetInput_->text()));
    refreshAdaptersButton_->setEnabled(true);
    defaultsButton_->setEnabled(!defaultTargetText_.isEmpty());
    adapterCombo_->setEnabled(true);
    targetInput_->setEnabled(true);

    statusProgressBar_->setVisible(false);

    if (resultModel_->rowCount() == 0) {
        showStatusMessage(completedScanWasCanceled_
                              ? "Scan stopped. No responding hosts detected."
                              : "Scan complete. No responding hosts detected.");
    } else {
        showStatusMessage(completedScanWasCanceled_
                              ? QString("Scan stopped. %1 host(s) detected.").arg(resultModel_->rowCount())
                              : QString("Scan complete. %1 host(s) detected.").arg(resultModel_->rowCount()));
    }

    cancelRequested_.reset();
}

void ScannerWindow::updateProgress(int current, int total)
{
    statusProgressBar_->setRange(0, total <= 0 ? 1 : total);
    statusProgressBar_->setValue(current);
}

void ScannerWindow::addOrUpdateResultRow(const ScanResult &result)
{
    if (result.ip.isEmpty()) {
        return;
    }
    const ViewportAnchor anchor = captureViewportAnchor();
    resultModel_->upsertResult(result);
    applyTableFilters();
    restoreViewportAnchor(anchor);
    updateDetailsPaneForCurrentSelection();
}

void ScannerWindow::queueResultForDisplay(const ScanResult &result)
{
    if (result.ip.isEmpty()) {
        return;
    }
    pendingDisplayResults_.append(result);
    if (!resultFlushTimer_->isActive()) {
        resultFlushTimer_->start();
    }
}

void ScannerWindow::flushPendingResults()
{
    constexpr int kMaximumRowsPerUiTurn = 64;
    if (pendingDisplayResults_.isEmpty()) {
        return;
    }
    const ViewportAnchor anchor = captureViewportAnchor();
    const int count = std::min(kMaximumRowsPerUiTurn,
                               static_cast<int>(pendingDisplayResults_.size()));
    for (int i = 0; i < count; ++i) {
        resultModel_->upsertResult(pendingDisplayResults_.takeLast());
    }
    applyTableFilters();
    restoreViewportAnchor(anchor);
    updateDetailsPaneForCurrentSelection();
    if (!pendingDisplayResults_.isEmpty()) {
        resultFlushTimer_->start(0);
    } else if (scanCompletionPending_) {
        completeScanPresentation();
    }
}

void ScannerWindow::handleTableDoubleClick(int row, int column)
{
    if (column != ColServices) {
        return;
    }

    const ScanResult result = resultModel_->resultAt(row);
    const QString ip = result.ip;
    const QList<ServiceHit> services = result.services;
    if (services.isEmpty()) {
        return;
    }

    if (services.size() == 1) {
        openService(ip, services.first());
        return;
    }

    QMenu menu(this);
    for (const ServiceHit &service : services) {
        QAction *action = menu.addAction(
            QString("Open %1").arg(serviceEvidenceText(service.label,
                                                       service.port,
                                                       service.evidence)));
        connect(action, &QAction::triggered, this, [this, ip, service]() {
            openService(ip, service);
        });
    }
    menu.exec(QCursor::pos());
}

void ScannerWindow::showTableContextMenu(const QPoint &pos)
{
    const QModelIndex index = table_->indexAt(pos);
    if (!index.isValid()) {
        return;
    }

    table_->setCurrentIndex(index);

    const ScanResult result = resultModel_->resultAt(index.row());
    const QString ip = result.ip;
    const QList<ServiceHit> services = result.services;

    QMenu menu(this);
    QAction *copyCellAction = menu.addAction("Copy Cell");
    QAction *copyIpAction = menu.addAction("Copy IP");
    QAction *copyHostAction = menu.addAction("Copy Hostname");
    QAction *copyMacAction = menu.addAction("Copy MAC");
    QAction *copyVendorAction = menu.addAction("Copy Vendor");
    QAction *copyServicesAction = menu.addAction("Copy Services");
    QAction *copyRowAction = menu.addAction("Copy Row");

    menu.addSeparator();
    QList<QAction *> openActions;
    for (const ServiceHit &service : services) {
        QAction *action = menu.addAction(
            QString("Open %1").arg(serviceEvidenceText(service.label,
                                                       service.port,
                                                       service.evidence)));
        openActions.append(action);
    }

    QAction *selectedAction = menu.exec(table_->viewport()->mapToGlobal(pos));
    if (selectedAction == nullptr) {
        return;
    }

    if (selectedAction == copyCellAction) {
        copyCellText(index.row(), index.column());
        return;
    }
    if (selectedAction == copyIpAction) {
        copyCellText(index.row(), ColIp);
        return;
    }
    if (selectedAction == copyHostAction) {
        copyCellText(index.row(), ColHostname);
        return;
    }
    if (selectedAction == copyMacAction) {
        copyCellText(index.row(), ColMac);
        return;
    }
    if (selectedAction == copyVendorAction) {
        copyCellText(index.row(), ColVendor);
        return;
    }
    if (selectedAction == copyServicesAction) {
        copyCellText(index.row(), ColServices);
        return;
    }
    if (selectedAction == copyRowAction) {
        const QString rowText = QString("%1\t%2\t%3\t%4\t%5")
                                    .arg(cellText(index.row(), ColIp))
                                    .arg(cellText(index.row(), ColHostname))
                                    .arg(cellText(index.row(), ColMac))
                                    .arg(cellText(index.row(), ColVendor))
                                    .arg(cellText(index.row(), ColServices));
        QApplication::clipboard()->setText(rowText);
        return;
    }

    for (int i = 0; i < openActions.size(); ++i) {
        if (selectedAction == openActions[i]) {
            openService(ip, services[i]);
            return;
        }
    }
}

void ScannerWindow::showHeaderContextMenu(const QPoint &pos)
{
    QHeaderView *header = table_->horizontalHeader();
    if (header == nullptr) {
        return;
    }

    QMenu menu(this);
    for (int col = 0; col < ColCount; ++col) {
        const QString title = resultModel_->headerData(
            col, Qt::Horizontal, Qt::DisplayRole).toString();
        QAction *action = menu.addAction(title);
        action->setCheckable(true);
        action->setChecked(!table_->isColumnHidden(col));
        action->setData(col);
    }

    QAction *selected = menu.exec(header->viewport()->mapToGlobal(pos));
    if (selected == nullptr) {
        return;
    }

    const int col = selected->data().toInt();
    if (col < 0 || col >= ColCount) {
        return;
    }

    const bool currentlyVisible = !table_->isColumnHidden(col);
    if (currentlyVisible) {
        int visibleCount = 0;
        for (int i = 0; i < ColCount; ++i) {
            if (!table_->isColumnHidden(i)) {
                ++visibleCount;
            }
        }
        if (visibleCount <= 1) {
            QMessageBox::warning(this, "Columns", "At least one column must remain visible.");
            return;
        }
    }

    table_->setColumnHidden(col, currentlyVisible);
    saveSettings();
}

void ScannerWindow::toggleSearchBar()
{
    const bool visible = !searchBar_->isVisible();
    searchBar_->setVisible(visible);
    if (visible) {
        searchInput_->setFocus();
        searchInput_->selectAll();
    } else {
        searchInput_->clear();
        searchScopeCombo_->setCurrentIndex(0);
        applyTableFilters();
    }
}

void ScannerWindow::copySelectedCell()
{
    const QModelIndex current = table_->currentIndex();
    if (!current.isValid()) {
        return;
    }

    copyCellText(current.row(), current.column());
}

void ScannerWindow::applyTableFilters()
{
    for (int row = 0; row < resultModel_->rowCount(); ++row) {
        table_->setRowHidden(row, !rowMatchesFilters(row));
    }
}

bool ScannerWindow::rowMatchesFilters(int row) const
{
    const QString query = searchInput_ ? searchInput_->text().trimmed() : QString();
    if (query.isEmpty()) {
        return true;
    }

    const QString scope = searchScopeCombo_ ? searchScopeCombo_->currentData().toString() : QString("all");
    const QString hostname = cellText(row, ColHostname);
    const QString vendor = cellText(row, ColVendor);
    const QString services = cellText(row, ColServices);
    const QString mac = cellText(row, ColMac);

    if (scope == "vendor") {
        return vendor.contains(query, Qt::CaseInsensitive);
    }
    if (scope == "services") {
        return services.contains(query, Qt::CaseInsensitive);
    }
    if (scope == "ip") {
        return cellText(row, ColIp).contains(query, Qt::CaseInsensitive);
    }
    if (scope == "hostname") {
        return hostname.contains(query, Qt::CaseInsensitive);
    }
    if (scope == "mac") {
        return mac.contains(query, Qt::CaseInsensitive);
    }
    if (scope == "oui") {
        const QString qPrefix = normalizeOuiPrefix(query);
        if (qPrefix.isEmpty()) {
            return mac.contains(query, Qt::CaseInsensitive);
        }
        return normalizeOuiPrefix(mac).startsWith(qPrefix, Qt::CaseInsensitive);
    }

    if (vendor.contains(query, Qt::CaseInsensitive)) {
        return true;
    }
    if (services.contains(query, Qt::CaseInsensitive)) {
        return true;
    }
    if (mac.contains(query, Qt::CaseInsensitive)) {
        return true;
    }
    if (hostname.contains(query, Qt::CaseInsensitive)) {
        return true;
    }
    const QString ip = cellText(row, ColIp);
    return ip.contains(query, Qt::CaseInsensitive);
}

void ScannerWindow::copyCellText(int row, int column) const
{
    QApplication::clipboard()->setText(cellText(row, column));
}

QString ScannerWindow::cellText(int row, int column) const
{
    const QModelIndex index = resultModel_->index(row, column);
    if (!index.isValid()) {
        return {};
    }
    return index.data(Qt::DisplayRole).toString();
}

void ScannerWindow::exportCsv()
{
    if (resultModel_->rowCount() == 0) {
        QMessageBox::warning(this, "Export CSV", "Nothing to export. Run a scan first.");
        return;
    }

    QStringList headers;
    QVector<QStringList> rows;
    QVector<bool> rowVisible;
    for (int col = 0; col < ColCount; ++col) {
        headers.append(resultModel_->headerData(
            col, Qt::Horizontal, Qt::DisplayRole).toString());
    }
    for (int row = 0; row < resultModel_->rowCount(); ++row) {
        QStringList fields;
        for (int col = 0; col < ColCount; ++col) {
            fields.append(cellText(row, col));
        }
        rows.append(fields);
        rowVisible.append(!table_->isRowHidden(row));
    }
    const QList<int> columnList = visibleColumnsInDisplayOrder();
    const QVector<int> columns(columnList.begin(), columnList.end());
    const int filteredCount = static_cast<int>(
        std::count(rowVisible.cbegin(), rowVisible.cend(), true));

    QDialog scopeDialog(this);
    scopeDialog.setWindowTitle("Export CSV");
    auto *scopeLayout = new QVBoxLayout(&scopeDialog);
    scopeLayout->addWidget(new QLabel(
        "Rows to export (current table order):", &scopeDialog));
    auto *filteredRows = new QRadioButton(
        QString("Filtered rows (%1)").arg(filteredCount), &scopeDialog);
    auto *allRows = new QRadioButton(
        QString("All rows (%1)").arg(rows.size()), &scopeDialog);
    filteredRows->setChecked(true);
    scopeLayout->addWidget(filteredRows);
    scopeLayout->addWidget(allRows);
    auto *columnNotice = new QLabel(
        "Columns: visible columns in current display order", &scopeDialog);
    columnNotice->setWordWrap(true);
    scopeLayout->addWidget(columnNotice);
    auto *scopeButtons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &scopeDialog);
    connect(scopeButtons, &QDialogButtonBox::accepted,
            &scopeDialog, &QDialog::accept);
    connect(scopeButtons, &QDialogButtonBox::rejected,
            &scopeDialog, &QDialog::reject);
    scopeLayout->addWidget(scopeButtons);
    if (scopeDialog.exec() != QDialog::Accepted) {
        return;
    }

    const QString path = QFileDialog::getSaveFileName(
        this, "Export CSV", "scan-results.csv", "CSV Files (*.csv)");
    if (path.isEmpty()) {
        return;
    }

    const CsvExportData data = CsvExporter::selectTable(
        headers, rows, rowVisible, columns, filteredRows->isChecked());

    const CsvExportOutcome outcome = CsvExporter::exportFile(path, data);
    if (outcome.status != CsvExportStatus::Success) {
        QMessageBox::warning(this, "Export CSV", outcome.error);
        return;
    }
    showStatusMessage(QString("Exported CSV to %1").arg(path));
}

void ScannerWindow::printTable()
{
    if (resultModel_->rowCount() == 0) {
        QMessageBox::warning(this, "Print", "Nothing to print. Run a scan first.");
        return;
    }

    QPrinter printer;
    QPrintDialog dialog(&printer, this);
    dialog.setWindowTitle("Print Scan Results");
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    QString html = "<html><body><h3>Open IP Scanner Results</h3><table border='1' cellspacing='0' cellpadding='4'><tr>";
    const QList<int> columns = visibleColumnsInDisplayOrder();
    for (int col : columns) {
        html += QString("<th>%1</th>").arg(resultModel_->headerData(
            col, Qt::Horizontal, Qt::DisplayRole).toString().toHtmlEscaped());
    }
    html += "</tr>";

    for (int row = 0; row < resultModel_->rowCount(); ++row) {
        html += "<tr>";
        for (int col : columns) {
            html += QString("<td>%1</td>").arg(cellText(row, col).toHtmlEscaped());
        }
        html += "</tr>";
    }
    html += "</table></body></html>";

    QTextDocument doc;
    doc.setHtml(html);
    doc.print(&printer);
}

void ScannerWindow::showSettingsDialog()
{
    // Category list + stacked pages keeps a large settings surface organized.
    QDialog dialog(this);
    dialog.setObjectName("settingsDialog");
    dialog.setWindowTitle("Settings");
    dialog.setFixedSize(settingslayout::kDialogWidth, settingslayout::kDialogHeight);
    dialog.setModal(true);

    auto *layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(settingslayout::kOuterMargin,
                               settingslayout::kOuterMargin,
                               settingslayout::kOuterMargin,
                               settingslayout::kOuterMargin);
    layout->setSpacing(settingslayout::kSectionSpacing);
    auto *body = new QWidget(&dialog);
    auto *bodyLayout = new QHBoxLayout(body);
    bodyLayout->setContentsMargins(0, 0, 0, 0);
    bodyLayout->setSpacing(settingslayout::kSectionSpacing);

    auto *categories = new QListWidget(body);
    categories->setObjectName("settingsCategories");
    categories->setFixedWidth(settingslayout::kNavigationWidth);
    categories->addItems({"Appearance", "Services", "Performance", "Programs", "OUI Prefixes", "Toolbar"});

    auto *pages = new QStackedWidget(body);
    const auto addSettingsPage = [pages](QWidget *page) {
        auto *scroll = new QScrollArea(pages);
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setWidgetResizable(true);
        scroll->setWidget(page);
        pages->addWidget(scroll);
    };
    bodyLayout->addWidget(categories);
    bodyLayout->addWidget(pages, 1);
    layout->addWidget(body, 1);

    auto *appearancePage = new QWidget(pages);
    auto *appearanceLayout = new QVBoxLayout(appearancePage);
    appearanceLayout->setContentsMargins(settingslayout::kOuterMargin,
                                          settingslayout::kOuterMargin,
                                          settingslayout::kOuterMargin,
                                          settingslayout::kOuterMargin);
    appearanceLayout->setSpacing(settingslayout::kControlSpacing);
    auto *ipCheck = new QCheckBox("Show IP Address column", appearancePage);
    auto *hostCheck = new QCheckBox("Show Hostname column", appearancePage);
    auto *macCheck = new QCheckBox("Show MAC Address column", appearancePage);
    auto *vendorCheck = new QCheckBox("Show Vendor column", appearancePage);
    auto *svcCheck = new QCheckBox("Show Services column", appearancePage);
    auto *macFormatCombo = new QComboBox(appearancePage);
    macFormatCombo->addItem("AA:BB:CC:DD:EE:FF (upper, colon)", MacColonUpper);
    macFormatCombo->addItem("aa:bb:cc:dd:ee:ff (lower, colon)", MacColonLower);
    macFormatCombo->addItem("AA-BB-CC-DD-EE-FF (upper, hyphen)", MacHyphenUpper);
    macFormatCombo->addItem("aa-bb-cc-dd-ee-ff (lower, hyphen)", MacHyphenLower);
    macFormatCombo->addItem("aabb.ccdd.eeff (Cisco)", MacCiscoDot);
    macFormatCombo->addItem("AABBCCDDEEFF (plain upper)", MacPlainUpper);
    macFormatCombo->addItem("aabbccddeeff (plain lower)", MacPlainLower);
    macFormatCombo->setCurrentIndex(std::max(0, macFormatCombo->findData(macDisplayFormat_)));
    auto *targetFormatCombo = new QComboBox(appearancePage);
    targetFormatCombo->setObjectName("settingsTargetFormat");
    targetFormatCombo->addItem("CIDR (192.168.1.0/24)", "cidr");
    targetFormatCombo->addItem(
        "Begin/end range (192.168.1.1-192.168.1.254)", "range");
    targetFormatCombo->setCurrentIndex(
        targetTextFormat_ == TargetTextFormat::Cidr ? 0 : 1);
    ipCheck->setChecked(!table_->isColumnHidden(ColIp));
    hostCheck->setChecked(!table_->isColumnHidden(ColHostname));
    macCheck->setChecked(!table_->isColumnHidden(ColMac));
    vendorCheck->setChecked(!table_->isColumnHidden(ColVendor));
    svcCheck->setChecked(!table_->isColumnHidden(ColServices));
    appearanceLayout->addWidget(ipCheck);
    appearanceLayout->addWidget(hostCheck);
    appearanceLayout->addWidget(macCheck);
    appearanceLayout->addWidget(vendorCheck);
    appearanceLayout->addWidget(svcCheck);
    auto *macFormatForm = new QFormLayout();
    macFormatForm->setHorizontalSpacing(settingslayout::kSectionSpacing);
    macFormatForm->setVerticalSpacing(settingslayout::kControlSpacing);
    macFormatForm->addRow("MAC display format:", macFormatCombo);
    macFormatForm->addRow("Generated targets:", targetFormatCombo);
    appearanceLayout->addLayout(macFormatForm);
    appearanceLayout->addStretch(1);
    addSettingsPage(appearancePage);

    auto *servicesPage = new QWidget(pages);
    auto *servicesLayout = new QVBoxLayout(servicesPage);
    servicesLayout->setContentsMargins(settingslayout::kOuterMargin,
                                        settingslayout::kOuterMargin,
                                        settingslayout::kOuterMargin,
                                        settingslayout::kOuterMargin);
    servicesLayout->setSpacing(settingslayout::kControlSpacing);
    QHash<QString, QCheckBox *> serviceChecks;
    for (const ServiceDefinition &def : availableServices()) {
        auto *check = new QCheckBox(QString("Probe %1 (%2)").arg(def.label).arg(def.port), servicesPage);
        check->setChecked(enabledServiceIds_.contains(def.id));
        serviceChecks.insert(def.id, check);
        servicesLayout->addWidget(check);
    }
    servicesLayout->addStretch(1);
    addSettingsPage(servicesPage);

    auto *performancePage = new QWidget(pages);
    auto *performanceLayout = new QGridLayout(performancePage);
    performanceLayout->setContentsMargins(settingslayout::kOuterMargin,
                                           settingslayout::kOuterMargin,
                                           settingslayout::kOuterMargin,
                                           settingslayout::kOuterMargin);
    performanceLayout->setHorizontalSpacing(settingslayout::kSectionSpacing);
    performanceLayout->setVerticalSpacing(settingslayout::kControlSpacing);
    performanceLayout->setColumnMinimumWidth(0, settingslayout::kRowLabelWidth);
    auto *workerSlider = new QSlider(Qt::Horizontal, performancePage);
    workerSlider->setObjectName("settingsWorkerSlider");
    workerSlider->setRange(1, kMaxParallelProbes);
    workerSlider->setFixedWidth(settingslayout::kSliderWidth);
    workerSlider->setTickInterval(1);
    workerSlider->setTickPosition(QSlider::TicksBelow);
    workerSlider->setValue(maxParallelProbes_);
    auto *workerLabel = new QLabel(performancePage);
    workerLabel->setObjectName("settingsWorkerValue");
    workerLabel->setFixedWidth(settingslayout::kValueWidth);
    workerLabel->setText(QString("%1 thread%2").arg(maxParallelProbes_).arg(maxParallelProbes_ == 1 ? "" : "s"));
    connect(workerSlider, &QSlider::valueChanged, &dialog, [workerLabel](int value) {
        workerLabel->setText(QString("%1 thread%2").arg(value).arg(value == 1 ? "" : "s"));
    });
    auto *workerRowLabel = new QLabel("Scan workers:", performancePage);
    workerRowLabel->setObjectName("settingsWorkerRowLabel");
    workerRowLabel->setFixedWidth(settingslayout::kRowLabelWidth);
    performanceLayout->addWidget(workerRowLabel, 0, 0);
    performanceLayout->addWidget(workerSlider, 0, 1);
    performanceLayout->addWidget(workerLabel, 0, 2);

    auto *accuracySlider = new QSlider(Qt::Horizontal, performancePage);
    accuracySlider->setObjectName("settingsAccuracySlider");
    accuracySlider->setRange(0, 3);
    accuracySlider->setFixedWidth(settingslayout::kSliderWidth);
    accuracySlider->setTickInterval(1);
    accuracySlider->setTickPosition(QSlider::TicksBelow);
    accuracySlider->setValue(accuracyLevel_);
    auto *accuracyValueLabel = new QLabel(performancePage);
    accuracyValueLabel->setObjectName("settingsAccuracyValue");
    accuracyValueLabel->setFixedWidth(settingslayout::kValueWidth);
    accuracyValueLabel->setText(accuracyLabel());
    auto *accuracyDetailsLabel = new QLabel(performancePage);
    accuracyDetailsLabel->setObjectName("settingsAccuracyDetails");
    accuracyDetailsLabel->setFixedHeight(settingslayout::kDynamicDescriptionHeight);
    accuracyDetailsLabel->setWordWrap(true);
    accuracyDetailsLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    accuracyDetailsLabel->setText(scanBudgetProfileSummary(accuracyLevel_));
    connect(accuracySlider,
            &QSlider::valueChanged,
            &dialog,
            [accuracyValueLabel, accuracyDetailsLabel](int value) {
        const int clamped = std::clamp(value, 0, 3);
        const char *labels[] = {"Fast", "Balanced", "High", "Maximum"};
        accuracyValueLabel->setText(labels[clamped]);
        accuracyDetailsLabel->setText(scanBudgetProfileSummary(clamped));
    });
    auto *accuracyRowLabel = new QLabel("Accuracy:", performancePage);
    accuracyRowLabel->setObjectName("settingsAccuracyRowLabel");
    accuracyRowLabel->setFixedWidth(settingslayout::kRowLabelWidth);
    performanceLayout->addWidget(accuracyRowLabel, 1, 0);
    performanceLayout->addWidget(accuracySlider, 1, 1);
    performanceLayout->addWidget(accuracyValueLabel, 1, 2);
    performanceLayout->addWidget(accuracyDetailsLabel, 2, 1, 1, 2);
    auto *accuracyHelp = new QLabel(
        "Fast gives a quick lay of the land. Higher settings repeat ping and port probes "
        "with longer waits so intermittent or sleeping devices have more chances to respond.",
        performancePage);
    accuracyHelp->setObjectName("settingsAccuracyHelp");
    accuracyHelp->setWordWrap(true);
    performanceLayout->addWidget(accuracyHelp, 3, 0, 1, 3);
    performanceLayout->setRowStretch(4, 1);
    addSettingsPage(performancePage);

    auto *programsPage = new QWidget(pages);
    auto *programsLayout = new QFormLayout(programsPage);
    programsLayout->setContentsMargins(settingslayout::kOuterMargin,
                                        settingslayout::kOuterMargin,
                                        settingslayout::kOuterMargin,
                                        settingslayout::kOuterMargin);
    programsLayout->setHorizontalSpacing(settingslayout::kSectionSpacing);
    programsLayout->setVerticalSpacing(settingslayout::kControlSpacing);
    programsLayout->setRowWrapPolicy(QFormLayout::WrapLongRows);
    QHash<QString, QLineEdit *> commandEdits;
    for (const ServiceDefinition &def : availableServices()) {
        if (def.isWeb) {
            continue;
        }
        auto *edit = new QLineEdit(programsPage);
        edit->setText(customCommands_.value(def.id));
        edit->setPlaceholderText("Use {host} and optionally {port} / {url}");
        edit->setMaxLength(512);
        edit->setValidator(new QRegularExpressionValidator(
            QRegularExpression("^[\\x20-\\x7E]*$"), edit));
        programsLayout->addRow(QString("%1 command:").arg(def.label), edit);
        commandEdits.insert(def.id, edit);
    }
    addSettingsPage(programsPage);

    auto *ouiPage = new QWidget(pages);
    auto *ouiLayout = new QVBoxLayout(ouiPage);
    ouiLayout->setContentsMargins(settingslayout::kOuterMargin,
                                  settingslayout::kOuterMargin,
                                  settingslayout::kOuterMargin,
                                  settingslayout::kOuterMargin);
    ouiLayout->setSpacing(settingslayout::kControlSpacing);
    auto *ouiHelp = new QLabel("Custom OUI overrides (one per line): PREFIX=Vendor\nExamples: 00163E=My Lab Vendor, 00:11:22=VendorX", ouiPage);
    ouiHelp->setWordWrap(true);
    auto *ouiEdit = new QPlainTextEdit(ouiPage);
    QStringList customLines;
    for (auto it = customOuiVendors_.begin(); it != customOuiVendors_.end(); ++it) {
        customLines.append(QString("%1=%2").arg(it.key(), it.value()));
    }
    std::sort(customLines.begin(), customLines.end());
    ouiEdit->setPlainText(customLines.join("\n"));
    ouiEdit->setPlaceholderText("Leave blank if no custom overrides are needed.");
    ouiEdit->setMaximumBlockCount(2000);
    ouiLayout->addWidget(ouiHelp);
    ouiLayout->addWidget(ouiEdit, 1);
    addSettingsPage(ouiPage);

    auto *toolbarPage = new QWidget(pages);
    auto *toolbarPageLayout = new QVBoxLayout(toolbarPage);
    toolbarPageLayout->setContentsMargins(settingslayout::kOuterMargin,
                                           settingslayout::kOuterMargin,
                                           settingslayout::kOuterMargin,
                                           settingslayout::kOuterMargin);
    toolbarPageLayout->setSpacing(settingslayout::kControlSpacing);
    auto *styleForm = new QFormLayout();
    styleForm->setHorizontalSpacing(settingslayout::kSectionSpacing);
    styleForm->setVerticalSpacing(settingslayout::kControlSpacing);
    auto *displayModeCombo = new QComboBox(toolbarPage);
    displayModeCombo->addItem("Icon only", 0);
    displayModeCombo->addItem("Icon + Text", 1);
    displayModeCombo->addItem("Text only", 2);
    displayModeCombo->setCurrentIndex(std::clamp(toolbarDisplayMode_, 0, 2));
    styleForm->addRow("Default style:", displayModeCombo);

    auto *itemModeCombo = new QComboBox(toolbarPage);
    itemModeCombo->addItem("Default", -1);
    itemModeCombo->addItem("Icon only", 0);
    itemModeCombo->addItem("Icon + Text", 1);
    itemModeCombo->addItem("Text only", 2);
    itemModeCombo->setEnabled(false);
    styleForm->addRow("Selected action:", itemModeCombo);
    toolbarPageLayout->addLayout(styleForm);

    const QHash<QString, QString> labels = {
        {"targets_label", "Targets Label"},
        {"target_input", "Targets Input"},
        {"scan", "Start/Stop"},
        {"sep", "--- separator ---"},
        {"spacer", "--- expanding spacer ---"},
        {"auto", "Auto"},
        {"find", "Find"},
        {"terminal", "Terminal"},
        {"adapter_label", "Adapter Label"},
        {"adapter_combo", "Adapter Selector"},
        {"refresh", "Refresh"}
    };
    QMap<QString, int> toolbarModesDraft = toolbarItemDisplayModes_;
    const auto addToolbarItem = [&labels](QListWidget *list, const QString &id) {
        auto *item = new QListWidgetItem(labels.value(id, id), list);
        item->setData(Qt::UserRole, id);
    };

    auto *listsRow = new QWidget(toolbarPage);
    auto *listsLayout = new QHBoxLayout(listsRow);
    listsLayout->setContentsMargins(0, 0, 0, 0);
    listsLayout->setSpacing(settingslayout::kControlSpacing);
    auto *availableList = new QListWidget(listsRow);
    auto *currentList = new QListWidget(listsRow);
    availableList->setSelectionMode(QAbstractItemView::SingleSelection);
    currentList->setSelectionMode(QAbstractItemView::SingleSelection);

    const QStringList allIds = {"sep", "spacer", "targets_label", "target_input", "scan", "auto", "find", "terminal", "adapter_label", "adapter_combo", "refresh"};
    for (const QString &id : allIds) {
        if (id == "sep" || id == "spacer" || !toolbarOrder_.contains(id)) {
            addToolbarItem(availableList, id);
        }
    }
    for (const QString &id : toolbarOrder_) {
        if (kToolbarAllowedIds.contains(id)) {
            addToolbarItem(currentList, id);
        }
    }

    auto *moveButtons = new QWidget(listsRow);
    auto *moveButtonsLayout = new QVBoxLayout(moveButtons);
    moveButtonsLayout->setContentsMargins(0, 0, 0, 0);
    moveButtonsLayout->setSpacing(settingslayout::kControlSpacing);
    moveButtonsLayout->addStretch(1);
    auto *addButton = new QPushButton(">", moveButtons);
    auto *removeButton = new QPushButton("<", moveButtons);
    auto *upButton = new QPushButton("Up", moveButtons);
    auto *downButton = new QPushButton("Down", moveButtons);
    auto *defaultsButton = new QPushButton("Defaults", moveButtons);
    moveButtonsLayout->addWidget(addButton);
    moveButtonsLayout->addWidget(removeButton);
    moveButtonsLayout->addWidget(upButton);
    moveButtonsLayout->addWidget(downButton);
    moveButtonsLayout->addWidget(defaultsButton);
    moveButtonsLayout->addStretch(1);

    listsLayout->addWidget(availableList, 1);
    listsLayout->addWidget(moveButtons);
    listsLayout->addWidget(currentList, 1);
    toolbarPageLayout->addWidget(new QLabel("Configure toolbar actions:", toolbarPage));
    toolbarPageLayout->addWidget(listsRow, 1);

    connect(addButton, &QPushButton::clicked, &dialog, [availableList, currentList, addToolbarItem]() {
        const int row = availableList->currentRow();
        if (row < 0) {
            return;
        }
        QListWidgetItem *selected = availableList->item(row);
        if (selected == nullptr) {
            return;
        }
        const QString id = selected->data(Qt::UserRole).toString();
        if (id == "sep" || id == "spacer") {
            addToolbarItem(currentList, id);
            currentList->setCurrentRow(currentList->count() - 1);
            return;
        }
        QListWidgetItem *item = availableList->takeItem(row);
        currentList->addItem(item);
        currentList->setCurrentItem(item);
    });
    connect(removeButton, &QPushButton::clicked, &dialog, [availableList, currentList, addToolbarItem]() {
        const int row = currentList->currentRow();
        if (row < 0) {
            return;
        }
        QListWidgetItem *item = currentList->takeItem(row);
        const QString id = item->data(Qt::UserRole).toString();
        if (id == "sep" || id == "spacer") {
            delete item;
            return;
        }
        bool alreadyInAvailable = false;
        for (int i = 0; i < availableList->count(); ++i) {
            if (availableList->item(i)->data(Qt::UserRole).toString() == id) {
                alreadyInAvailable = true;
                break;
            }
        }
        if (alreadyInAvailable) {
            delete item;
            return;
        }
        addToolbarItem(availableList, id);
        delete item;
    });
    connect(upButton, &QPushButton::clicked, &dialog, [currentList]() {
        const int row = currentList->currentRow();
        if (row <= 0) {
            return;
        }
        QListWidgetItem *item = currentList->takeItem(row);
        currentList->insertItem(row - 1, item);
        currentList->setCurrentRow(row - 1);
    });
    connect(downButton, &QPushButton::clicked, &dialog, [currentList]() {
        const int row = currentList->currentRow();
        if (row < 0 || row >= currentList->count() - 1) {
            return;
        }
        QListWidgetItem *item = currentList->takeItem(row);
        currentList->insertItem(row + 1, item);
        currentList->setCurrentRow(row + 1);
    });
    connect(defaultsButton,
            &QPushButton::clicked,
            &dialog,
            [availableList,
             currentList,
             allIds,
             addToolbarItem,
             displayModeCombo,
             itemModeCombo,
             &toolbarModesDraft]() {
        availableList->clear();
        currentList->clear();
        displayModeCombo->setCurrentIndex(
            displayModeCombo->findData(0));
        for (const QString &id : kToolbarButtonIds) {
            toolbarModesDraft[id] = -1;
        }
        itemModeCombo->setCurrentIndex(
            itemModeCombo->findData(-1));
        for (const QString &id : allIds) {
            if (id == "sep" || id == "spacer") {
                addToolbarItem(availableList, id);
            }
        }
        for (const QString &id : kToolbarDefaultOrder) {
            addToolbarItem(currentList, id);
        }
        for (const QString &id : allIds) {
            if (id == "sep" || id == "spacer") {
                continue;
            }
            if (!kToolbarDefaultOrder.contains(id)) {
                addToolbarItem(availableList, id);
            }
        }
    });
    connect(currentList, &QListWidget::currentItemChanged, &dialog, [itemModeCombo, &toolbarModesDraft](QListWidgetItem *current, QListWidgetItem *) {
        if (current == nullptr) {
            itemModeCombo->setEnabled(false);
            itemModeCombo->setCurrentIndex(0);
            return;
        }
        const QString id = current->data(Qt::UserRole).toString();
        if (!kToolbarButtonIds.contains(id)) {
            itemModeCombo->setEnabled(false);
            itemModeCombo->setCurrentIndex(0);
            return;
        }
        itemModeCombo->setEnabled(true);
        const int mode = toolbarModesDraft.value(id, -1);
        const int idx = std::max(0, itemModeCombo->findData(mode));
        itemModeCombo->setCurrentIndex(idx);
    });
    connect(itemModeCombo, &QComboBox::currentIndexChanged, &dialog, [currentList, itemModeCombo, &toolbarModesDraft](int) {
        QListWidgetItem *current = currentList->currentItem();
        if (current == nullptr) {
            return;
        }
        const QString id = current->data(Qt::UserRole).toString();
        if (!kToolbarButtonIds.contains(id)) {
            return;
        }
        toolbarModesDraft[id] = itemModeCombo->currentData().toInt();
    });
    if (currentList->count() > 0) {
        currentList->setCurrentRow(0);
    }
    addSettingsPage(toolbarPage);

    connect(categories, &QListWidget::currentRowChanged, pages, &QStackedWidget::setCurrentIndex);
    categories->setCurrentRow(0);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    buttons->setObjectName("settingsButtons");
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    if (!ipCheck->isChecked() && !hostCheck->isChecked() && !macCheck->isChecked() &&
        !vendorCheck->isChecked() && !svcCheck->isChecked()) {
        QMessageBox::warning(this, "Settings", "At least one column must remain visible.");
        return;
    }

    QHash<QString, QString> parsedOuiVendors;
    QString ouiError;
    if (!parseCustomOuiOverrides(
            ouiEdit->toPlainText(), &parsedOuiVendors, &ouiError)) {
        QMessageBox::warning(this, "Invalid OUI overrides", ouiError);
        return;
    }
    QHash<QString, QString> parsedCommands = customCommands_;
    for (auto it = commandEdits.begin(); it != commandEdits.end(); ++it) {
        const QString command = it.value()->text().trimmed();
        if (!command.isEmpty() && !isSafeTextInput(command, 512)) {
            QMessageBox::warning(
                this,
                "Settings",
                QString("Invalid command for service '%1'.").arg(it.key()));
            return;
        }
        parsedCommands[it.key()] = command;
    }

    updateWorkerLabel(workerSlider->value());
    accuracyLevel_ = std::clamp(accuracySlider->value(), 0, 3);

    table_->setColumnHidden(ColIp, !ipCheck->isChecked());
    table_->setColumnHidden(ColHostname, !hostCheck->isChecked());
    table_->setColumnHidden(ColMac, !macCheck->isChecked());
    table_->setColumnHidden(ColVendor, !vendorCheck->isChecked());
    table_->setColumnHidden(ColServices, !svcCheck->isChecked());
    const int newMacDisplayFormat = macFormatCombo->currentData().toInt();
    if (newMacDisplayFormat >= MacColonUpper && newMacDisplayFormat <= MacPlainLower &&
        newMacDisplayFormat != macDisplayFormat_) {
        macDisplayFormat_ = newMacDisplayFormat;
        refreshDisplayedMacAddresses();
    }
    const TargetTextFormat newTargetTextFormat =
        targetFormatCombo->currentData().toString() == "range"
            ? TargetTextFormat::Range
            : TargetTextFormat::Cidr;
    const bool targetTextFormatChanged =
        newTargetTextFormat != targetTextFormat_;
    targetTextFormat_ = newTargetTextFormat;

    enabledServiceIds_.clear();
    for (const ServiceDefinition &def : availableServices()) {
        if (serviceChecks.contains(def.id) && serviceChecks[def.id]->isChecked()) {
            enabledServiceIds_.insert(def.id);
        }
    }

    customCommands_ = parsedCommands;
    customOuiVendors_ = parsedOuiVendors;

    toolbarDisplayMode_ = displayModeCombo->currentData().toInt();
    toolbarItemDisplayModes_ = toolbarModesDraft;
    toolbarOrder_.clear();
    for (int i = 0; i < currentList->count(); ++i) {
        const QString id = currentList->item(i)->data(Qt::UserRole).toString();
        if (!kToolbarAllowedIds.contains(id)) {
            continue;
        }
        if ((id == "sep" || id == "spacer") || !toolbarOrder_.contains(id)) {
            toolbarOrder_.append(id);
        }
    }
    bool hasVisibleControl = false;
    for (const QString &id : toolbarOrder_) {
        if (id != "sep" && id != "spacer") {
            hasVisibleControl = true;
            break;
        }
    }
    if (toolbarOrder_.isEmpty() || !hasVisibleControl) {
        toolbarOrder_ = kToolbarDefaultOrder;
    }
    rebuildMainToolbar();

    if (targetTextFormatChanged) {
        const int preferred = preferredAdapterIndex();
        const DefaultTargetPlan defaultPlan =
            preferred >= 0
                ? buildDefaultTargetPlanForAdapter(
                      adapters_[preferred].interfaceName)
                : DefaultTargetPlan{};
        defaultTargetText_ = defaultPlan.targetText;
        if (!userCustomizedTargets_) {
            applyDefaultTargets();
        }
    }

    applyTableColumnSizing();
    saveSettings();
    updateProbeSummary();
}

void ScannerWindow::showAboutDialog()
{
    const QString version = QCoreApplication::applicationVersion().isEmpty()
                                ? QString("Unknown")
                                : QCoreApplication::applicationVersion();
    QMessageBox::about(this,
                       "About Open IP Scanner",
                       QString("Open IP Scanner v%1\n\n").arg(version) +
                       "Qt6 desktop IP scanner with adapter-aware scanning, custom target parsing,"
                       " service probing, and CSV export.");
}

void ScannerWindow::showHelpDialog()
{
    QDialog dialog(this);
    dialog.setWindowTitle("Usage Guide");
    dialog.resize(760, 520);
    auto *layout = new QVBoxLayout(&dialog);
    auto *browser = new QTextBrowser(&dialog);
    browser->setOpenExternalLinks(true);
    browser->setHtml(
        "<h2>Open IP Scanner Usage</h2>"
        "<p><b>Targets:</b> Enter CIDR, ranges, or single IPs. Examples:<br>"
        "<code>192.168.1.0/24</code>, <code>10.0.0.10-10.0.0.50</code>, "
        "<code>10.0.0.10-50</code>, <code>10.0.0.20</code>.</p>"
        "<p><b>Adapter selection:</b> Choose an adapter manually or use <b>Auto Select</b> "
        "to match entered targets to detected connected networks.</p>"
        "<p><b>Auto button:</b> Fills targets from connected routable networks. "
        "For a specific adapter, it fills only that adapter's detected network range(s).</p>"
        "<h3>Advanced</h3>"
        "<p><b>Performance:</b> Worker count controls parallel host probing. "
        "Higher values scan faster but increase network load.</p>"
        "<p><b>Accuracy:</b> Fast performs one short probe pass for a quick lay of the land. "
        "Balanced through Maximum progressively repeat ping and port probes and allow cached "
        "neighbor evidence time to become actively confirmed for intermittent, sleeping, or "
        "slower devices.</p>"
        "<p><b>Scan traffic:</b> The status bar summarizes the active mode before launch; hover "
        "it for exact attempts and enabled ports. Scans send ICMP echo requests, open TCP "
        "connections only to enabled service ports, may send HTTP HEAD, TLS handshakes, or "
        "SMTP EHLO and read bounded banners when those services are enabled, inspect the local "
        "adapter neighbor cache, and perform PTR, system-resolver, and interface-scoped mDNS "
        "reverse lookups for responding devices.</p>"
        "<p><b>Services:</b> Enable/disable per-port probing and configure launch commands in "
        "Settings &rarr; Programs. An unverified connection is shown as "
        "<code>Unknown:&lt;port&gt;</code>; a service name appears after a bounded protocol check "
        "confirms it.</p>"
        "<p><b>Details:</b> The details pane lists detected hostnames and services with short "
        "source labels. Opening it does not send extra network requests.</p>"
        "<p><b>Hostname diagnostics:</b> Help &rarr; Hostname Diagnostics shows resolver and "
        "Avahi health counts and can save a redacted JSON support bundle.</p>"
        "<p><b>Filtering:</b> Use Find to filter by IP, hostname, MAC, vendor, services, or OUI prefix.</p>"
        "<p><b>Privacy:</b> Target history is off by default. Settings can enable local history, "
        "optionally restore its last target on launch, or clear retained targets immediately.</p>"
        "<p><b>Safety:</b> Scan only networks you own or are authorized to test.</p>");
    layout->addWidget(browser, 1);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    layout->addWidget(buttons);
    dialog.exec();
}

void ScannerWindow::updateWorkerLabel(int value)
{
    maxParallelProbes_ = std::clamp(value, 1, kMaxParallelProbes);
}

QString ScannerWindow::accuracyLabel() const
{
    switch (std::clamp(accuracyLevel_, 0, 3)) {
    case 0:
        return "Fast";
    case 1:
        return "Balanced";
    case 2:
        return "High";
    case 3:
    default:
        return "Maximum";
    }
}

QString ScannerWindow::activeProbeSummary(bool detailed) const
{
    if (scanInProgress_ && hasActiveScanOptions_) {
        return probeSummary(
            activeScanOptions_, detailed, activeScanTargetRetained_);
    }
    ScanOptions options;
    options.accuracyLevel = accuracyLevel_;
    options.enabledServiceIds = enabledServiceIds_;
    const ScanBudgetProfile configuredBudget = scanBudgetProfile(accuracyLevel_);
    options.pingAttempts = configuredBudget.pingAttempts;
    options.pingTimeoutSeconds = configuredBudget.pingTimeoutSeconds;
    options.serviceAttempts = configuredBudget.serviceAttempts;
    return probeSummary(options, detailed, saveTargetHistory_);
}

QString ScannerWindow::probeSummary(const ScanOptions &options,
                                    bool detailed,
                                    bool targetRetained) const
{
    QStringList ports;
    bool sendsHttp = false;
    bool usesTls = false;
    bool sendsSmtpEhlo = false;
    bool readsBanners = false;
    for (const ServiceDefinition &definition : availableServices()) {
        if (!options.enabledServiceIds.contains(definition.id)) {
            continue;
        }
        ports.append(QString::number(definition.port));
        sendsHttp = sendsHttp || definition.id == "http" || definition.id == "https";
        usesTls = usesTls || definition.id == "https" || definition.id == "smtps465";
        sendsSmtpEhlo = sendsSmtpEhlo || definition.id == "smtp587";
        readsBanners = readsBanners || definition.id == "ssh" ||
                       definition.id == "ftp" || definition.id == "smtp25" ||
                       definition.id == "smtps465" || definition.id == "smtp587";
    }

    const QString history = targetRetained ? "history on" : "history off";
    if (!detailed) {
        static const std::array<const char *, 4> labels = {
            "Fast", "Balanced", "High", "Maximum"};
        const QString mode = QString::fromLatin1(
            labels[static_cast<std::size_t>(
                std::clamp(options.accuracyLevel, 0, 3))]);
        const QString tcp = ports.isEmpty()
                                ? "no TCP service ports"
                                : QString("TCP %1").arg(ports.join(','));
        return QString("%1 · ICMP + %2 + PTR/System/mDNS · %3")
            .arg(mode, tcp, history);
    }

    QStringList details;
    details.append(QString("ICMP: up to %1 echo attempt(s) per target with a %2-second timeout.")
                       .arg(options.pingAttempts)
                       .arg(options.pingTimeoutSeconds));
    details.append("Neighbor evidence: reads the selected adapter's local IPv4 neighbor cache; this does not transmit a separate neighbor-discovery packet.");
    if (ports.isEmpty()) {
        details.append("TCP: no service ports are enabled.");
    } else {
        details.append(QString("TCP: up to %1 connection attempt(s) to enabled port(s) %2, bound to the selected adapter.")
                           .arg(options.serviceAttempts)
                           .arg(ports.join(", ")));
    }
    QStringList applicationTraffic;
    if (sendsHttp) {
        applicationTraffic.append("HTTP HEAD on enabled HTTP/HTTPS ports");
    }
    if (usesTls) {
        applicationTraffic.append("TLS handshakes on enabled TLS ports");
    }
    if (sendsSmtpEhlo) {
        applicationTraffic.append("SMTP EHLO on port 587");
    }
    if (readsBanners) {
        applicationTraffic.append("bounded banner reads on enabled SSH/FTP/SMTP ports");
    }
    details.append(applicationTraffic.isEmpty()
                       ? "Application traffic: no application payloads are sent."
                       : QString("Application traffic: %1.")
                             .arg(applicationTraffic.join("; ")));
    details.append("Names: responding devices receive explicit PTR, system-resolver, and interface-scoped mDNS reverse lookups.");
    details.append(targetRetained
                       ? "Privacy: target history is saved locally."
                       : "Privacy: target history is not saved.");
    return details.join('\n');
}

bool ScannerWindow::confirmScanAuthorization(const ScanOptions &options)
{
    QSettings settings("OpenIPScanner", "OpenIPScanner");
    if (settings.value("safety/authorization_ack_version", 0).toInt() >=
        kAuthorizationAcknowledgementVersion) {
        return true;
    }

    QMessageBox dialog(this);
    dialog.setIcon(QMessageBox::Warning);
    dialog.setWindowTitle("Authorized Scanning Required");
    dialog.setText("Scan only networks and devices you own or are explicitly authorized to test.");
    dialog.setInformativeText(probeSummary(options, true, saveTargetHistory_));
    dialog.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    dialog.button(QMessageBox::Yes)->setText("I Am Authorized — Start Scan");
    dialog.setDefaultButton(QMessageBox::Cancel);
    if (dialog.exec() != QMessageBox::Yes) {
        return false;
    }
    settings.setValue("safety/authorization_ack_version",
                      kAuthorizationAcknowledgementVersion);
    settings.sync();
    return settings.status() == QSettings::NoError;
}

void ScannerWindow::updateProbeSummary()
{
    if (probeSummaryLabel_ == nullptr) {
        return;
    }
    probeSummaryLabel_->setText(activeProbeSummary(false));
    probeSummaryLabel_->setToolTip(activeProbeSummary(true));
}

ScanOptions ScannerWindow::captureScanOptions(const AdapterInfo &adapter) const
{
    ScanOptions options;
    options.accuracyLevel = std::clamp(accuracyLevel_, 0, 3);
    const ScanBudgetProfile budget = scanBudgetProfile(options.accuracyLevel);
    options.maxParallelProbes = std::clamp(maxParallelProbes_, 1, kMaxParallelProbes);
    options.interfaceName = adapter.interfaceName;
    options.interfaceLabel = adapter.interfaceLabel;
    options.localIp = adapter.localIp;
    options.localMac = adapter.localMac;
    options.dnsSuffixes = adapter.dnsSuffixes;
    options.pingAttempts = budget.pingAttempts;
    options.pingTimeoutSeconds = budget.pingTimeoutSeconds;
    options.serviceAttempts = budget.serviceAttempts;
    options.serviceTimeoutMs = budget.serviceTimeoutMs;
    options.neighborConfirmationMs = budget.neighborConfirmationMs;
    options.macDisplayFormat = macDisplayFormat_;
    options.enabledServiceIds = enabledServiceIds_;
    int serviceWaitUnits = 0;
    for (const ServiceDefinition &definition : availableServices()) {
        if (options.enabledServiceIds.contains(definition.id)) {
            serviceWaitUnits += serviceProbeWaitUnits(definition.id);
        }
    }
    options.targetDeadlineMs = targetDeadlineForProfile(
        budget, hostnameTimeoutProfile(options.accuracyLevel), serviceWaitUnits);
    options.builtInOuiVendors = builtInOuiVendors_;
    options.customOuiVendors = customOuiVendors_;
    return options;
}

void ScannerWindow::applyDefaultSettings()
{
    maxParallelProbes_ = 4;
    accuracyLevel_ = 1;
    saveTargetHistory_ = false;
    rememberLastTargetOnLaunch_ = false;
    targetTextFormat_ = TargetTextFormat::Cidr;
    pendingLastTarget_.clear();
    toolbarDisplayMode_ = 0;
    macDisplayFormat_ = MacColonUpper;
    toolbarItemDisplayModes_.clear();
    for (const QString &id : kToolbarButtonIds) {
        toolbarItemDisplayModes_.insert(id, -1);
    }
    enabledServiceIds_.clear();
    enabledServiceIds_ << "http" << "https" << "ssh" << "rdp";

    customCommands_.clear();
    const QString terminal = preferredTerminalProgram();
    customCommands_.insert("ssh", QString("%1 -e ssh {host}").arg(terminal));
    // Prefer desktop-handler RDP launcher (typically Remmina) for GUI credential flow.
    customCommands_.insert("rdp", "xdg-open rdp://{host}");
    customCommands_.insert("ftp", "xdg-open ftp://{host}");
    customCommands_.insert("telnet", QString("%1 -e telnet {host}").arg(terminal));
    customCommands_.insert("smb", "xdg-open smb://{host}");

    customOuiVendors_.clear();

    toolbarOrder_ = kToolbarDefaultOrder;
}

bool ScannerWindow::migrateSettings(QSettings &settings, QString *error)
{
    return SettingsStore::migrate(settings, error);
}

void ScannerWindow::loadSettings()
{
    QSettings settings("OpenIPScanner", "OpenIPScanner");
    QString migrationError;
    if (!migrateSettings(settings, &migrationError)) {
        QMessageBox::warning(this, "Settings Migration", migrationError);
        showStatusMessage(migrationError);
    }

    // On Wayland, compositor controls window placement, so only restore size.
    const bool isWayland = QGuiApplication::platformName().contains("wayland", Qt::CaseInsensitive);
    const QByteArray savedGeometry = settings.value("window/geometry").toByteArray();
    const QSize savedSize = settings.value("window/size").toSize();
    if (isWayland) {
        if (savedSize.isValid()) {
            resize(savedSize);
        }
    } else if (!savedGeometry.isEmpty()) {
        restoreGeometry(savedGeometry);
    } else if (savedSize.isValid()) {
        resize(savedSize);
    }

    maxParallelProbes_ = std::clamp(settings.value("performance/max_parallel_probes", 4).toInt(), 1, kMaxParallelProbes);
    accuracyLevel_ = std::clamp(settings.value("performance/accuracy_level", 1).toInt(), 0, 3);
    saveTargetHistory_ = settings.value("targets/save_history", false).toBool();
    rememberLastTargetOnLaunch_ =
        saveTargetHistory_ && settings.value("targets/remember_last", false).toBool();
    targetTextFormat_ = settings.value("targets/generated_format", "cidr").toString() ==
                                "range"
                            ? TargetTextFormat::Range
                            : TargetTextFormat::Cidr;
    pendingLastTarget_.clear();
    if (rememberLastTargetAction_ != nullptr) {
        const QSignalBlocker blocker(rememberLastTargetAction_);
        rememberLastTargetAction_->setChecked(rememberLastTargetOnLaunch_);
        rememberLastTargetAction_->setEnabled(saveTargetHistory_);
    }
    if (saveTargetHistoryAction_ != nullptr) {
        const QSignalBlocker blocker(saveTargetHistoryAction_);
        saveTargetHistoryAction_->setChecked(saveTargetHistory_);
    }
    if (clearTargetHistoryAction_ != nullptr) {
        clearTargetHistoryAction_->setEnabled(saveTargetHistory_);
    }
    toolbarDisplayMode_ = std::clamp(settings.value("toolbar/display_mode", 0).toInt(), 0, 2);
    macDisplayFormat_ = std::clamp(settings.value("appearance/mac_display_format", static_cast<int>(MacColonUpper)).toInt(),
                                   static_cast<int>(MacColonUpper),
                                   static_cast<int>(MacPlainLower));
    toolbarItemDisplayModes_.clear();
    for (const QString &id : kToolbarButtonIds) {
        const QString key = QString("toolbar/item_mode_%1").arg(id);
        const int fallback = -1;
        const int value = settings.contains(key) ? settings.value(key).toInt() : fallback;
        toolbarItemDisplayModes_.insert(id, std::clamp(value, -1, 2));
    }
    table_->setColumnHidden(ColIp, !settings.value("appearance/show_ip", true).toBool());
    table_->setColumnHidden(ColHostname, !settings.value("appearance/show_hostname", true).toBool());
    table_->setColumnHidden(ColMac, !settings.value("appearance/show_mac", true).toBool());
    table_->setColumnHidden(ColVendor, !settings.value("appearance/show_vendor", true).toBool());
    table_->setColumnHidden(ColServices, !settings.value("appearance/show_services", true).toBool());
    const bool showDetails = settings.value("appearance/show_details_pane", false).toBool();
    setDetailsPaneVisible(showDetails);
    if (showDetailsPaneAction_ != nullptr) {
        showDetailsPaneAction_->setChecked(showDetails);
    }
    if (table_->isColumnHidden(ColIp) && table_->isColumnHidden(ColHostname) &&
        table_->isColumnHidden(ColMac) && table_->isColumnHidden(ColVendor) &&
        table_->isColumnHidden(ColServices)) {
        table_->setColumnHidden(ColIp, false);
    }

    if (settings.contains("services/enabled_ids")) {
        const QStringList enabledServices =
            settings.value("services/enabled_ids").toStringList();
        enabledServiceIds_.clear();
        for (const QString &id : enabledServices) {
            if (isSafeTextInput(id, 32)) {
                enabledServiceIds_.insert(id);
            }
        }
    }

    for (auto it = customCommands_.begin(); it != customCommands_.end(); ++it) {
        const QString key = QString("programs/%1").arg(it.key());
        const QString value = settings.value(key, it.value()).toString().trimmed();
        if (value.isEmpty() || isSafeTextInput(value, 512)) {
            it.value() = value;
        }
    }
    const QString preferredTerminal = preferredTerminalProgram();
    if (customCommands_.value("ssh").trimmed() == "x-terminal-emulator -e ssh {host}") {
        customCommands_["ssh"] = QString("%1 -e ssh {host}").arg(preferredTerminal);
    }
    if (customCommands_.value("telnet").trimmed() == "x-terminal-emulator -e telnet {host}") {
        customCommands_["telnet"] = QString("%1 -e telnet {host}").arg(preferredTerminal);
    }
    const QString rdpCmd = customCommands_.value("rdp").trimmed();
    if (rdpCmd == "xfreerdp /v:{host}" || rdpCmd == "xfreerdp /v:{host} /cert:ignore") {
        customCommands_["rdp"] = "xdg-open rdp://{host}";
    }

    const QStringList savedOrder = settings.value("toolbar/order").toStringList();
    if (!savedOrder.isEmpty()) {
        QStringList validated;
        for (const QString &id : savedOrder) {
            if (!kToolbarAllowedIds.contains(id)) {
                continue;
            }
            if ((id == "sep" || id == "spacer") || !validated.contains(id)) {
                validated.append(id);
            }
        }
        bool hasVisibleControl = false;
        for (const QString &id : validated) {
            if (id != "sep" && id != "spacer") {
                hasVisibleControl = true;
                break;
            }
        }
        toolbarOrder_ = hasVisibleControl ? validated : kToolbarDefaultOrder;
    }
    if (toolbarOrder_.isEmpty()) {
        toolbarOrder_ = kToolbarDefaultOrder;
    }
    rebuildMainToolbar();

    targetHistory_.clear();
    const QStringList history = saveTargetHistory_
                                    ? settings.value("targets/history").toStringList()
                                    : QStringList{};
    for (const QString &entry : history) {
        const QString trimmed = entry.trimmed();
        if (!trimmed.isEmpty() && isSafeTextInput(trimmed, 2048)) {
            targetHistory_.append(trimmed);
        }
    }
    targetHistory_.removeDuplicates();
    while (targetHistory_.size() > 30) {
        targetHistory_.removeLast();
    }
    targetHistoryModel_->setStringList(targetHistory_);
    if (rememberLastTargetOnLaunch_) {
        const QString savedTarget = settings.value("targets/last_input").toString().trimmed();
        if (!savedTarget.isEmpty() && isSafeTextInput(savedTarget, 2048)) {
            pendingLastTarget_ = savedTarget;
            targetInput_->setText(savedTarget);
            userCustomizedTargets_ = true;
            validateTargetLimitFeedback(savedTarget);
        }
    }

    customOuiVendors_.clear();
    const int count = settings.beginReadArray("oui/custom_entries");
    for (int i = 0; i < count; ++i) {
        settings.setArrayIndex(i);
        const QString prefix = normalizeOuiPrefix(settings.value("prefix").toString());
        const QString vendor = settings.value("vendor").toString().trimmed();
        if (!prefix.isEmpty() && !vendor.isEmpty() && isSafeTextInput(vendor, 120)) {
            customOuiVendors_.insert(prefix, vendor);
        }
    }
    settings.endArray();
}

void ScannerWindow::saveSettings() const
{
    QSettings settings("OpenIPScanner", "OpenIPScanner");
    settings.setValue("settings/schema_version", kSettingsSchemaVersion);
    settings.setValue("window/geometry", saveGeometry());
    settings.setValue("window/size", size());
    settings.setValue("performance/max_parallel_probes", maxParallelProbes_);
    settings.setValue("performance/accuracy_level", accuracyLevel_);
    settings.setValue("toolbar/display_mode", toolbarDisplayMode_);
    settings.setValue("toolbar/order", toolbarOrder_);
    for (const QString &id : kToolbarButtonIds) {
        settings.setValue(QString("toolbar/item_mode_%1").arg(id),
                          toolbarItemDisplayModes_.value(id, -1));
    }
    settings.setValue("appearance/show_ip", !table_->isColumnHidden(ColIp));
    settings.setValue("appearance/show_hostname", !table_->isColumnHidden(ColHostname));
    settings.setValue("appearance/show_mac", !table_->isColumnHidden(ColMac));
    settings.setValue("appearance/mac_display_format", macDisplayFormat_);
    settings.setValue("appearance/show_vendor", !table_->isColumnHidden(ColVendor));
    settings.setValue("appearance/show_services", !table_->isColumnHidden(ColServices));
    settings.setValue("appearance/show_details_pane", detailsPane_->isVisible());
    settings.setValue("services/enabled_ids", QStringList(enabledServiceIds_.begin(), enabledServiceIds_.end()));

    for (auto it = customCommands_.begin(); it != customCommands_.end(); ++it) {
        settings.setValue(QString("programs/%1").arg(it.key()), it.value());
    }
    settings.setValue("targets/save_history", saveTargetHistory_);
    settings.setValue("targets/remember_last", rememberLastTargetOnLaunch_);
    settings.setValue("targets/generated_format",
                      targetTextFormat_ == TargetTextFormat::Cidr ? "cidr"
                                                                  : "range");
    if (saveTargetHistory_) {
        if (targetHistory_.isEmpty()) {
            settings.remove("targets/history");
        } else {
            settings.setValue("targets/history", targetHistory_);
        }
        const QString lastInput = targetInput_->text().trimmed();
        if (rememberLastTargetOnLaunch_ && !lastInput.isEmpty()) {
            settings.setValue("targets/last_input", lastInput);
        } else {
            settings.remove("targets/last_input");
        }
    } else {
        settings.remove("targets/history");
        settings.remove("targets/last_input");
    }

    settings.beginWriteArray("oui/custom_entries");
    int index = 0;
    for (auto it = customOuiVendors_.begin(); it != customOuiVendors_.end(); ++it, ++index) {
        settings.setArrayIndex(index);
        settings.setValue("prefix", it.key());
        settings.setValue("vendor", it.value());
    }
    settings.endArray();
}

void ScannerWindow::scheduleSettingsSave()
{
    settingsSaveTimer_->start();
}

bool ScannerWindow::parseCustomOuiOverrides(
    const QString &text,
    QHash<QString, QString> *vendors,
    QString *error)
{
    return OuiDatabase::parseOverrides(text, vendors, error);
}

bool ScannerWindow::isSafeTextInput(const QString &text, int maxLength)
{
    if (text.size() > maxLength) {
        return false;
    }
    for (const QChar ch : text) {
        if (ch == QChar::Null || ch.category() == QChar::Other_Control) {
            return false;
        }
    }
    return true;
}

bool ScannerWindow::recordTargetHistory(const QString &text)
{
    if (!saveTargetHistory_) {
        return false;
    }
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty() || !isSafeTextInput(trimmed, 2048)) {
        return false;
    }

    targetHistory_.removeAll(trimmed);
    targetHistory_.prepend(trimmed);
    while (targetHistory_.size() > 30) {
        targetHistory_.removeLast();
    }
    targetHistoryModel_->setStringList(targetHistory_);
    QSettings settings("OpenIPScanner", "OpenIPScanner");
    QString error;
    if (!persistTargetHistorySettings(settings,
                                      targetHistory_,
                                      targetInput_->text().trimmed(),
                                      rememberLastTargetOnLaunch_,
                                      &error)) {
        targetHistory_.removeAll(trimmed);
        targetHistoryModel_->setStringList(targetHistory_);
        QMessageBox::warning(this, "Target History", error);
        showStatusMessage(error);
        return false;
    }
    return true;
}

void ScannerWindow::setTargetHistoryRetention(bool enabled)
{
    if (!enabled && saveTargetHistory_) {
        QSettings settings("OpenIPScanner", "OpenIPScanner");
        QString error;
        if (!clearRetainedTargetSettings(settings, true, &error)) {
            if (saveTargetHistoryAction_ != nullptr) {
                const QSignalBlocker blocker(saveTargetHistoryAction_);
                saveTargetHistoryAction_->setChecked(true);
            }
            QMessageBox::warning(this, "Target History", error);
            showStatusMessage(error);
            return;
        }
    }
    saveTargetHistory_ = enabled;
    if (!enabled) {
        activeScanTargetRetained_ = false;
        rememberLastTargetOnLaunch_ = false;
        targetHistory_.clear();
        targetHistoryModel_->setStringList({});
    }
    if (saveTargetHistoryAction_ != nullptr &&
        saveTargetHistoryAction_->isChecked() != enabled) {
        const QSignalBlocker blocker(saveTargetHistoryAction_);
        saveTargetHistoryAction_->setChecked(enabled);
    }
    if (rememberLastTargetAction_ != nullptr) {
        const QSignalBlocker blocker(rememberLastTargetAction_);
        rememberLastTargetAction_->setEnabled(enabled);
        rememberLastTargetAction_->setChecked(rememberLastTargetOnLaunch_);
    }
    if (clearTargetHistoryAction_ != nullptr) {
        clearTargetHistoryAction_->setEnabled(enabled);
    }
    saveSettings();
    updateProbeSummary();
}

void ScannerWindow::clearTargetHistory()
{
    QSettings settings("OpenIPScanner", "OpenIPScanner");
    QString error;
    if (!clearRetainedTargetSettings(settings, false, &error)) {
        QMessageBox::warning(this, "Target History", error);
        showStatusMessage(error);
        return;
    }
    targetHistory_.clear();
    activeScanTargetRetained_ = false;
    targetHistoryModel_->setStringList({});
    rememberLastTargetOnLaunch_ = false;
    pendingLastTarget_.clear();
    if (rememberLastTargetAction_ != nullptr) {
        const QSignalBlocker blocker(rememberLastTargetAction_);
        rememberLastTargetAction_->setChecked(false);
    }
    updateProbeSummary();
    showStatusMessage("Saved target history cleared.");
}

bool ScannerWindow::clearRetainedTargetSettings(QSettings &settings,
                                                bool disableRetention,
                                                QString *error)
{
    return SettingsStore::clearRetainedTargets(settings, disableRetention, error);
}

bool ScannerWindow::persistTargetHistorySettings(QSettings &settings,
                                                 const QStringList &history,
                                                 const QString &lastInput,
                                                 bool rememberLast,
                                                 QString *error)
{
    return SettingsStore::persistTargetHistory(
        settings, history, lastInput, rememberLast, error);
}

QList<int> ScannerWindow::visibleColumnsInDisplayOrder() const
{
    QList<int> columns;
    QHeaderView *header = table_->horizontalHeader();
    for (int visual = 0; visual < header->count(); ++visual) {
        const int logical = header->logicalIndex(visual);
        if (!table_->isColumnHidden(logical)) {
            columns.append(logical);
        }
    }
    return columns;
}

void ScannerWindow::showStatusMessage(const QString &text)
{
    statusTextLabel_->setText(text);
}

void ScannerWindow::validateTargetLimitFeedback(const QString &text)
{
    QString error;
    const QString trimmed = text.trimmed();
    if (!trimmed.isEmpty() && isSafeTextInput(trimmed, 2048)) {
        parseTargetsInput(trimmed, &error);
    }

    if (error.startsWith("Too many targets")) {
        targetInput_->setStyleSheet("QLineEdit { color: #D9534F; }");
        targetLimitWarningActive_ = true;
        showStatusMessage(error);
    } else {
        targetInput_->setStyleSheet({});
        if (targetLimitWarningActive_ && !scanInProgress_) {
            showStatusMessage("Ready.");
        }
        targetLimitWarningActive_ = false;
    }
}

void ScannerWindow::rebuildMainToolbar()
{
    if (mainToolbar_ == nullptr || toolbarLayout_ == nullptr) {
        return;
    }

    // Rebuild toolbar controls from persisted order/visibility config.
    while (QLayoutItem *item = toolbarLayout_->takeAt(0)) {
        if (QWidget *w = item->widget()) {
            w->setParent(nullptr);
        }
        delete item;
    }

    const QHash<QString, QWidget *> widgets = {
        {"targets_label", targetsLabel_},
        {"target_input", targetInput_},
        {"scan", scanButton_},
        {"auto", defaultsButton_},
        {"find", findButton_},
        {"terminal", terminalButton_},
        {"adapter_label", adapterLabel_},
        {"adapter_combo", adapterCombo_},
        {"refresh", refreshAdaptersButton_}
    };

    for (const QString &id : toolbarOrder_) {
        if (id == "sep") {
            auto *line = new QFrame(toolbarContainer_);
            line->setFrameShape(QFrame::VLine);
            line->setFrameShadow(QFrame::Sunken);
            toolbarLayout_->addWidget(line);
            continue;
        }
        if (id == "spacer") {
            auto *spacer = new QWidget(toolbarContainer_);
            spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            toolbarLayout_->addWidget(spacer, 1);
            continue;
        }
        QWidget *widget = widgets.value(id, nullptr);
        if (widget != nullptr) {
            widget->setParent(toolbarContainer_);
            if (id == "target_input") {
                toolbarLayout_->addWidget(widget, 1);
            } else {
                toolbarLayout_->addWidget(widget);
            }
        }
    }

    applyToolbarDisplayMode();
}

void ScannerWindow::applyToolbarDisplayMode()
{
    if (mainToolbar_ == nullptr) {
        return;
    }

    // Per-action mode overrides global style (icon/text).
    const auto buttonMode = [this](const QString &id) {
        const int overrideMode = toolbarItemDisplayModes_.value(id, -1);
        return overrideMode < 0 ? toolbarDisplayMode_
                                : std::clamp(overrideMode, 0, 2);
    };
    const auto applyButton = [](QPushButton *button, const QString &label, const QIcon &icon, int mode, int iconOnlyWidth = 0) {
        if (button == nullptr) {
            return;
        }
        const bool iconOnly = (mode == 0);
        const bool textOnly = (mode == 2);
        button->setText(iconOnly ? QString() : label);
        button->setIcon(textOnly ? QIcon() : icon);
        if (iconOnly && iconOnlyWidth > 0) {
            button->setFixedWidth(iconOnlyWidth);
        } else {
            button->setMinimumWidth(0);
            button->setMaximumWidth(QWIDGETSIZE_MAX);
            button->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Preferred);
        }
    };

    applyButton(scanButton_, scanInProgress_ ? "Stop" : "Scan",
                scanInProgress_ ? stopIcon_ : playIcon_, buttonMode("scan"), 32);
    applyButton(defaultsButton_, "Auto", style()->standardIcon(QStyle::SP_DriveNetIcon), buttonMode("auto"));
    applyButton(findButton_, "Find", QIcon::fromTheme("edit-find", style()->standardIcon(QStyle::SP_FileDialogContentsView)),
                buttonMode("find"), 32);
    applyButton(terminalButton_, "Terminal", QIcon::fromTheme("utilities-terminal", style()->standardIcon(QStyle::SP_ComputerIcon)), buttonMode("terminal"));
    applyButton(refreshAdaptersButton_, "Refresh", style()->standardIcon(QStyle::SP_BrowserReload), buttonMode("refresh"), 32);
}

QString ScannerWindow::rowIdentityKey(int row) const
{
    return resultModel_->identityAt(row);
}

int ScannerWindow::findRowByIdentity(const QString &identityKey) const
{
    return resultModel_->rowForIdentity(identityKey);
}

ScannerWindow::ViewportAnchor ScannerWindow::captureViewportAnchor() const
{
    ViewportAnchor anchor;
    anchor.scrollValue = table_->verticalScrollBar()->value();
    QModelIndex top = table_->indexAt(QPoint(1, 1));
    if (!top.isValid()) {
        for (int row = 0; row < resultModel_->rowCount(); ++row) {
            if (!table_->isRowHidden(row)) {
                top = resultModel_->index(row, 0);
                break;
            }
        }
    }
    if (top.isValid()) {
        anchor.identity = rowIdentityKey(top.row());
        anchor.pixelOffset = table_->visualRect(top).top();
    }
    return anchor;
}

void ScannerWindow::restoreViewportAnchor(const ViewportAnchor &anchor)
{
    if (anchor.identity.isEmpty()) {
        table_->verticalScrollBar()->setValue(anchor.scrollValue);
        return;
    }
    const int row = findRowByIdentity(anchor.identity);
    if (row < 0 || table_->isRowHidden(row)) {
        table_->verticalScrollBar()->setValue(anchor.scrollValue);
        return;
    }
    const QModelIndex index = resultModel_->index(row, 0);
    table_->scrollTo(index, QAbstractItemView::PositionAtTop);
    table_->verticalScrollBar()->setValue(
        table_->verticalScrollBar()->value() - anchor.pixelOffset);
}

void ScannerWindow::setDetailsPaneVisible(bool visible)
{
    detailsPane_->setVisible(visible);
    if (visible) {
        updateDetailsPaneForCurrentSelection();
        QList<int> sizes = resultsSplitter_->sizes();
        if (sizes.size() == 2 && sizes[1] < 80) {
            const int total = std::max(1, sizes[0] + sizes[1]);
            resultsSplitter_->setSizes({static_cast<int>(total * 0.72), static_cast<int>(total * 0.28)});
        }
    }
}

void ScannerWindow::updateDetailsPaneForCurrentSelection()
{
    if (!detailsPane_->isVisible()) {
        return;
    }

    const QModelIndex current = table_->currentIndex();
    if (!current.isValid()) {
        detailsPane_->setPlainText("Select a device to view details.");
        return;
    }

    ScanOptions options;
    options.macDisplayFormat = macDisplayFormat_;
    detailsPane_->setHtml(collectDeviceDetails(
        resultModel_->resultAt(current.row()), options));
}

QList<ResolverEvent> ScannerWindow::resolverEventsForDisplayedResults() const
{
    QList<ResolverEvent> events;
    for (int row = 0; row < resultModel_->rowCount(); ++row) {
        events.append(resultModel_->resultAt(row).resolverEvents);
    }
    return events;
}

QByteArray ScannerWindow::resolverSupportBundle() const
{
    const QString version = QCoreApplication::applicationVersion().isEmpty()
                                ? QString(OPEN_IP_SCANNER_VERSION)
                                : QCoreApplication::applicationVersion();
    return resolverSupportBundleJson(resolverEventsForDisplayedResults(),
                                     version,
                                     QSysInfo::prettyProductName());
}

void ScannerWindow::showResolverDiagnostics()
{
    QDialog dialog(this);
    dialog.setWindowTitle("Hostname Diagnostics");
    dialog.resize(520, 360);
    auto *layout = new QVBoxLayout(&dialog);
    auto *summary = new QPlainTextEdit(&dialog);
    summary->setReadOnly(true);
    summary->setPlainText(resolverDiagnosticsText(
        resolverEventsForDisplayedResults()));
    layout->addWidget(summary, 1);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save |
                                             QDialogButtonBox::Close,
                                         &dialog);
    buttons->button(QDialogButtonBox::Save)->setText("Save Support Bundle...");
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    connect(buttons->button(QDialogButtonBox::Save),
            &QPushButton::clicked,
            &dialog,
            [this, &dialog]() {
                const QString path = QFileDialog::getSaveFileName(
                    &dialog,
                    "Save Support Bundle",
                    "open-ip-scanner-support.json",
                    "JSON files (*.json);;All files (*)");
                if (path.isEmpty()) {
                    return;
                }
                QSaveFile file(path);
                const QByteArray payload = resolverSupportBundle();
                if (!file.open(QIODevice::WriteOnly) ||
                    file.write(payload) != payload.size() ||
                    !file.commit()) {
                    QMessageBox::warning(
                        &dialog,
                        "Support Bundle",
                        QString("Could not save support bundle:\n%1")
                            .arg(file.errorString()));
                }
            });
    layout->addWidget(buttons);
    dialog.exec();
}

void ScannerWindow::applyTableColumnSizing()
{
    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    const QFontMetrics monoMetrics(mono);

    const int ipWidth = monoMetrics.horizontalAdvance("255.255.255.255") + 28;
    const int macWidth = monoMetrics.horizontalAdvance("AA:BB:CC:DD:EE:FF") + 28;

    table_->setColumnWidth(ColIp, std::max(table_->columnWidth(ColIp), ipWidth));
    table_->setColumnWidth(ColMac, std::max(table_->columnWidth(ColMac), macWidth));
    const int minHost = 220;
    if (table_->columnWidth(ColHostname) < minHost) {
        table_->setColumnWidth(ColHostname, minHost);
    }
    const int minVendor = 180;
    if (table_->columnWidth(ColVendor) < minVendor) {
        table_->setColumnWidth(ColVendor, minVendor);
    }
}

quint32 ScannerWindow::ipv4ToInt(const QHostAddress &address)
{
    return address.toIPv4Address();
}

QHostAddress ScannerWindow::intToIpv4(quint32 value)
{
    return QHostAddress(value);
}

QString ScannerWindow::hexGatewayToIp(const QString &hexGateway)
{
    bool ok = false;
    const quint32 value = hexGateway.toUInt(&ok, 16);
    if (!ok) {
        return {};
    }

    const quint32 b1 = value & 0x000000FFu;
    const quint32 b2 = (value & 0x0000FF00u) >> 8;
    const quint32 b3 = (value & 0x00FF0000u) >> 16;
    const quint32 b4 = (value & 0xFF000000u) >> 24;
    return QString("%1.%2.%3.%4").arg(b1).arg(b2).arg(b3).arg(b4);
}

bool ScannerWindow::parseIpv4(const QString &text, quint32 *out)
{
    QHostAddress address;
    if (!address.setAddress(text) || address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }

    if (out) {
        *out = address.toIPv4Address();
    }
    return true;
}

QString ScannerWindow::normalizeOuiPrefix(const QString &prefix)
{
    return OuiDatabase::normalizePrefix(prefix);
}

QIcon ScannerWindow::createPlayIcon()
{
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(34, 139, 34));

    QPolygon triangle;
    triangle << QPoint(4, 3) << QPoint(13, 8) << QPoint(4, 13);
    painter.drawPolygon(triangle);

    return QIcon(pixmap);
}

QIcon ScannerWindow::createStopIcon()
{
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(QColor(196, 0, 0));

    QPolygon octagon;
    octagon << QPoint(5, 1) << QPoint(11, 1) << QPoint(15, 5) << QPoint(15, 11)
            << QPoint(11, 15) << QPoint(5, 15) << QPoint(1, 11) << QPoint(1, 5);
    painter.drawPolygon(octagon);

    return QIcon(pixmap);
}

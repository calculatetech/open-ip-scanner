#include "scannerwindow.h"
#include "cancellablewait.h"
#include "settingslayout.h"

#include <QAction>
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
#include <QFrame>
#include <QFontDatabase>
#include <QFormLayout>
#include <QFontMetrics>
#include <QFuture>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHeaderView>
#include <QHostInfo>
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
#include <QStringListModel>
#include <QTableWidget>
#include <QTcpSocket>
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
#include <QtConcurrent>

#include <algorithm>
#include <atomic>
#include <limits>

namespace {
constexpr int kMaxHostsToScan = 4096;
constexpr int kMaxParallelProbes = 16;
constexpr int kSettingsSchemaVersion = 1;
constexpr int kIdentityRole = Qt::UserRole + 1;
// Default toolbar layout used on first launch and settings reset.
const QStringList kToolbarDefaultOrder = {
    "targets_label", "target_input", "scan", "sep", "auto", "find", "terminal", "sep", "adapter_label", "adapter_combo", "refresh"
};
const QSet<QString> kToolbarAllowedIds = {
    "targets_label", "target_input", "scan", "sep", "spacer", "auto", "find", "terminal", "adapter_label", "adapter_combo", "refresh"
};
const QSet<QString> kToolbarButtonIds = {"scan", "auto", "find", "terminal", "refresh"};

class SortKeyTableWidgetItem : public QTableWidgetItem {
public:
    using QTableWidgetItem::QTableWidgetItem;

    bool operator<(const QTableWidgetItem &other) const override
    {
        const QVariant lhs = data(Qt::UserRole);
        const QVariant rhs = other.data(Qt::UserRole);
        if (lhs.isValid() && rhs.isValid()) {
            bool lhsOk = false;
            bool rhsOk = false;
            const qulonglong lhsNum = lhs.toULongLong(&lhsOk);
            const qulonglong rhsNum = rhs.toULongLong(&rhsOk);
            if (lhsOk && rhsOk) {
                return lhsNum < rhsNum;
            }
            return QString::localeAwareCompare(lhs.toString(), rhs.toString()) < 0;
        }
        return QTableWidgetItem::operator<(other);
    }
};

QColor mutedServiceColor(const QString &serviceId)
{
    // Keep service tags distinct without creating a noisy color palette.
    if (serviceId == "http") return QColor("#476D78");
    if (serviceId == "https") return QColor("#3E6760");
    if (serviceId == "ssh") return QColor("#5A5872");
    if (serviceId == "rdp") return QColor("#6C5C4B");
    if (serviceId == "ftp") return QColor("#586A55");
    if (serviceId == "telnet") return QColor("#6D5454");
    if (serviceId == "smb") return QColor("#5E5D48");
    if (serviceId == "smtp25") return QColor("#5C5A47");
    if (serviceId == "smtps465") return QColor("#4F6354");
    if (serviceId == "smtp587") return QColor("#5A4F63");
    return QColor("#4E5A63");
}

QString serviceButtonStyle(const QColor &base)
{
    // Shared visual style for in-cell service action buttons.
    const QColor border = base.lighter(118);
    const QColor hover = base.lighter(112);
    const QColor press = base.darker(108);
    return QString(
        "QPushButton {"
        "  color: #F2F4F7;"
        "  background-color: %1;"
        "  border: 1px solid %2;"
        "  border-radius: 4px;"
        "  padding: 1px 8px;"
        "  font-size: 11px;"
        "}"
        "QPushButton:hover { background-color: %3; }"
        "QPushButton:pressed { background-color: %4; }")
        .arg(base.name(), border.name(), hover.name(), press.name());
}

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
        QRegularExpression("^[0-9.,/\\-\\s]*$"), targetInput_));
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

    table_ = new QTableWidget(central);
    table_->setColumnCount(ColCount);
    table_->setHorizontalHeaderLabels({"IP Address", "Hostname", "MAC Address", "Vendor", "Services"});
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectItems);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->setSortingEnabled(true);
    table_->horizontalHeader()->setSortIndicatorShown(true);
    table_->sortByColumn(ColIp, Qt::AscendingOrder);
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
        "QTableWidget {"
        "  border: 1px solid palette(midlight);"
        "  border-radius: 3px;"
        "  gridline-color: transparent;"
        "}"
        "QTableWidget::item {"
        "  border: 0px;"
        "}"
        "QTableWidget::item:selected {"
        "  background-color: #1769d1;"
        "  color: #ffffff;"
        "  border: 0px;"
        "}"
        "QTableWidget::item:selected:!active {"
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
    statusProgressBar_ = new QProgressBar(this);
    statusProgressBar_->setMinimumWidth(240);
    statusProgressBar_->setVisible(false);
    statusBar()->addWidget(statusTextLabel_, 1);
    statusBar()->addPermanentWidget(statusProgressBar_);

    applyDefaultSettings();
    loadOuiDatabase();
    // Internal overrides for local environments and virtual adapters.
    builtInOuiVendors_.insert("00163E", "Xensource");
    builtInOuiVendors_.insert("000C29", "VMware");
    builtInOuiVendors_.insert("001C42", "Parallels");
    builtInOuiVendors_.insert("080027", "Oracle VirtualBox");

    setupMenuBar();
    loadSettings();
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
    connect(targetInput_, &QLineEdit::textChanged, this, [this](const QString &) {
        if (rememberLastTargetOnLaunch_) {
            saveSettings();
        }
    });
    connect(adapterCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        validateTargetLimitFeedback(targetInput_->text());
    });
    connect(targetInput_, &QLineEdit::returnPressed, this, &ScannerWindow::startScan);
    connect(&scanWatcher_, &QFutureWatcher<QList<ScanResult>>::finished, this, &ScannerWindow::finishScan);
    connect(table_, &QWidget::customContextMenuRequested, this, &ScannerWindow::showTableContextMenu);
    connect(table_->horizontalHeader(), &QWidget::customContextMenuRequested, this, &ScannerWindow::showHeaderContextMenu);
    connect(table_, &QTableWidget::cellDoubleClicked, this, &ScannerWindow::handleTableDoubleClick);
    connect(table_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        updateDetailsPaneForCurrentSelection();
    });

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
    rememberLastTargetAction_ = settingsMenu->addAction("Remember Last Target On Launch");
    rememberLastTargetAction_->setCheckable(true);
    rememberLastTargetAction_->setChecked(false);
    connect(rememberLastTargetAction_, &QAction::toggled, this, [this](bool checked) {
        rememberLastTargetOnLaunch_ = checked;
        saveSettings();
    });
    showDetailsPaneAction_ = settingsMenu->addAction("Show Details Pane");
    showDetailsPaneAction_->setCheckable(true);
    showDetailsPaneAction_->setChecked(false);
    connect(showDetailsPaneAction_, &QAction::toggled, this, [this](bool checked) {
        setDetailsPaneVisible(checked);
        saveSettings();
    });

    QMenu *helpMenu = menuBar()->addMenu("Help");
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
    return ::buildDefaultTargetPlan(inputs, kMaxHostsToScan);
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
        scanButton_->setEnabled(hasNetwork);
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
            targetInput_->setText(QString("%1/32").arg(adapters_[selected].localIp));
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
    if (scanWatcher_.isRunning()) {
        if (cancelRequested_) {
            cancelRequested_->store(true);
            showStatusMessage("Stopping scan...");
        }
        return;
    }

    const QString targetText = targetInput_->text().trimmed();
    if (!isSafeTextInput(targetText, 2048)) {
        showStatusMessage("Invalid target input.");
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
    recordTargetHistory(targetText);

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

    servicesByIdentity_.clear();
    detailsByIdentity_.clear();
    table_->setRowCount(0);

    scanInProgress_ = true;
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
                if (cancellable::isCancelled(scanCancellation)) {
                    return;
                }
                addOrUpdateResultRow(result);
            }, Qt::QueuedConnection);
        };

        return scanHosts(scanOptions, hosts, scanCancellation, onProgress, onResult);
    });
    scanWatcher_.setFuture(future);
}

QList<QHostAddress> ScannerWindow::parseTargetsInput(const QString &text, QString *error) const
{
    QSet<quint32> unique;

    const QStringList tokens = text.split(',', Qt::SkipEmptyParts);
    if (tokens.isEmpty()) {
        if (error) {
            *error = "Enter at least one target (CIDR, range, or IP).";
        }
        return {};
    }

    for (const QString &rawToken : tokens) {
        const QString token = rawToken.trimmed();
        if (token.isEmpty()) {
            continue;
        }

        QList<QHostAddress> parsed;
        if (token.contains('/')) {
            const QStringList parts = token.split('/');
            if (parts.size() != 2) {
                if (error) {
                    *error = QString("Invalid CIDR: %1").arg(token);
                }
                return {};
            }

            bool ok = false;
            const int prefix = parts[1].toInt(&ok);
            QHostAddress ip;
            if (!ok || !ip.setAddress(parts[0]) || ip.protocol() != QAbstractSocket::IPv4Protocol || prefix < 1 || prefix > 32) {
                if (error) {
                    *error = QString("Invalid CIDR: %1").arg(token);
                }
                return {};
            }

            quint64 cidrHostCount = 0;
            if (prefix == 32) {
                cidrHostCount = 1;
            } else if (prefix == 31) {
                cidrHostCount = 2;
            } else {
                const int hostBits = 32 - prefix;
                cidrHostCount = (1ULL << hostBits) - 2ULL;
            }
            if (cidrHostCount > static_cast<quint64>(kMaxHostsToScan)) {
                if (error) {
                    *error = QString("Too many targets (%1 max). Narrow the range.").arg(kMaxHostsToScan);
                }
                return {};
            }
            parsed = hostsForCidr(ip, prefix);
        } else if (token.contains('-')) {
            parsed = hostsForRangeToken(token, error);
            if (parsed.isEmpty() && error && !error->isEmpty()) {
                return {};
            }
        } else {
            quint32 value = 0;
            if (!parseIpv4(token, &value)) {
                if (error) {
                    *error = QString("Invalid IP address: %1").arg(token);
                }
                return {};
            }
            parsed.append(intToIpv4(value));
        }

        for (const QHostAddress &host : parsed) {
            unique.insert(ipv4ToInt(host));
            if (unique.size() > kMaxHostsToScan) {
                if (error) {
                    *error = QString("Too many targets (%1 max). Narrow the range.").arg(kMaxHostsToScan);
                }
                return {};
            }
        }
    }

    QList<quint32> values = unique.values();
    std::sort(values.begin(), values.end());

    QList<QHostAddress> hosts;
    hosts.reserve(values.size());
    for (quint32 value : values) {
        hosts.append(intToIpv4(value));
    }

    return hosts;
}

QList<QHostAddress> ScannerWindow::hostsForCidr(const QHostAddress &base, int prefixLength) const
{
    QList<QHostAddress> hosts;

    const quint32 value = ipv4ToInt(base);
    const int hostBits = 32 - prefixLength;
    const quint32 mask = prefixLength == 0 ? 0 : (0xFFFFFFFFu << hostBits);
    const quint32 network = value & mask;

    if (prefixLength == 32) {
        hosts.append(intToIpv4(network));
        return hosts;
    }

    if (prefixLength == 31) {
        hosts.append(intToIpv4(network));
        hosts.append(intToIpv4(network + 1));
        return hosts;
    }

    const quint32 count = (hostBits >= 31) ? 0x7FFFFFFFu : (1u << hostBits);
    const quint32 usable = count >= 2 ? count - 2 : 0;
    for (quint32 i = 0; i < usable; ++i) {
        hosts.append(intToIpv4(network + 1 + i));
    }

    return hosts;
}

QList<QHostAddress> ScannerWindow::hostsForRangeToken(const QString &token, QString *error) const
{
    const QStringList parts = token.split('-');
    if (parts.size() != 2) {
        if (error) {
            *error = QString("Invalid range: %1").arg(token);
        }
        return {};
    }

    const QString left = parts[0].trimmed();
    const QString right = parts[1].trimmed();

    quint32 start = 0;
    if (!parseIpv4(left, &start)) {
        if (error) {
            *error = QString("Invalid range start: %1").arg(left);
        }
        return {};
    }

    quint32 end = 0;
    if (right.contains('.')) {
        if (!parseIpv4(right, &end)) {
            if (error) {
                *error = QString("Invalid range end: %1").arg(right);
            }
            return {};
        }
    } else {
        bool ok = false;
        const int lastOctet = right.toInt(&ok);
        if (!ok || lastOctet < 0 || lastOctet > 255) {
            if (error) {
                *error = QString("Invalid range end: %1").arg(right);
            }
            return {};
        }
        end = (start & 0xFFFFFF00u) | static_cast<quint32>(lastOctet);
    }

    if (start > end) {
        std::swap(start, end);
    }

    const quint64 hostCount = static_cast<quint64>(end) - static_cast<quint64>(start) + 1ULL;
    if (hostCount > static_cast<quint64>(kMaxHostsToScan)) {
        if (error) {
            *error = QString("Too many targets (%1 max). Narrow the range.").arg(kMaxHostsToScan);
        }
        return {};
    }

    QList<QHostAddress> hosts;
    hosts.reserve(static_cast<int>(end - start + 1));
    for (quint32 value = start; value <= end; ++value) {
        hosts.append(intToIpv4(value));
        if (value == 0xFFFFFFFFu) {
            break;
        }
    }

    return hosts;
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
                if (it->hostname == "Unknown" && result.hostname != "Unknown") {
                    it->hostname = result.hostname;
                    shouldEmit = true;
                }
                if (it->services.isEmpty() && !result.services.isEmpty()) {
                    it->services = result.services;
                    shouldEmit = true;
                }
                if (it->detailsText.isEmpty() && !result.detailsText.isEmpty()) {
                    it->detailsText = result.detailsText;
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
                if (ipString == options.localIp) {
                    alive = true;
                    discoveredMac = options.localMac;
                } else if (ipString == gatewayIp) {
                    alive = true;
                } else {
                    alive = pingHost(host, options, budget, cancelRequested);
                    if (!alive) {
                        neighbor = lookupNeighbor(
                            ipString, options.interfaceName, budget, cancelRequested);
                        if (neighbor.suppliesMacMetadata()) {
                            discoveredMac = neighbor.mac;
                        }
                        if (neighbor.establishesLiveness()) {
                            alive = true;
                        }
                    }
                    if (!alive && options.accuracyLevel >= 2 && !budget.expired()) {
                        discoveredServices = probeServices(
                            ipString, options.localIp, budget, cancelRequested, options);
                        alive = !discoveredServices.isEmpty();
                    }
                }

                if (alive) {
                    ScanResult result;
                    result.ip = ipString;
                    result.interfaceName = options.interfaceName;
                    for (const AliveHostStage stage : kAliveHostStageOrder) {
                        switch (stage) {
                        case AliveHostStage::Services:
                            result.services = discoveredServices.isEmpty()
                                                  ? probeServices(ipString,
                                                                  options.localIp,
                                                                  budget,
                                                                  cancelRequested,
                                                                  options)
                                                  : discoveredServices;
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
                        case AliveHostStage::Hostname:
                            result.hostname = ipString == options.localIp
                                                  ? QHostInfo::localHostName().trimmed()
                                                  : lookupHostname(
                                                        ipString, budget, cancelRequested);
                            break;
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
                            result.detailsText = collectDeviceDetails(
                                result, options.localIp, budget, cancelRequested, options);
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

QString ScannerWindow::lookupVendor(const QString &mac, const ScanOptions &options) const
{
    const QString prefix = normalizeOuiPrefix(mac);
    if (prefix.isEmpty()) {
        return "Unknown";
    }
    if (options.customOuiVendors.contains(prefix)) {
        return options.customOuiVendors.value(prefix);
    }
    return options.builtInOuiVendors.value(prefix, "Unknown");
}

QString ScannerWindow::lookupHostname(
    const QString &ip,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested) const
{
    const QString mdnsHost = lookupMdnsHostname(ip, budget, cancelRequested);
    if (!mdnsHost.isEmpty()) {
        return mdnsHost;
    }

    if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
        return "Unknown";
    }
    cancellable::WaitResult lookupResult = cancellable::WaitResult::Failed;
    const QHostInfo info = cancellable::lookupHost(
        ip, budget.clampTimeout(1500), cancelRequested, &lookupResult);
    if (lookupResult != cancellable::WaitResult::Completed) {
        return "Unknown";
    }
    if (info.error() != QHostInfo::NoError) {
        return "Unknown";
    }

    const QString host = info.hostName().trimmed();
    if (host.isEmpty() || host == ip) {
        return "Unknown";
    }

    return host;
}

QString ScannerWindow::lookupMdnsHostname(
    const QString &ip,
    const TargetBudget &budget,
    const std::shared_ptr<std::atomic_bool> &cancelRequested) const
{
#ifdef Q_OS_LINUX
    const QString resolver = QStandardPaths::findExecutable("avahi-resolve-address");
    if (resolver.isEmpty()) {
        return {};
    }

    QProcess proc;
    proc.start(resolver, {"-4", ip});
    if (cancellable::waitForProcess(
            proc,
            budget.clampTimeout(1200, kProcessCleanupReserveMs),
            cancelRequested,
            [&budget]() { return budget.remainingMs(); }) !=
        cancellable::WaitResult::Completed) {
        return {};
    }
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
        return {};
    }

    const QString output = QString::fromUtf8(proc.readAllStandardOutput()).trimmed();
    if (output.isEmpty()) {
        return {};
    }

    QStringList parts = output.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    if (parts.size() < 2) {
        return {};
    }
    QString host = parts.last().trimmed();
    if (host.endsWith('.')) {
        host.chop(1);
    }
    if (host.isEmpty() || host == ip) {
        return {};
    }
    return host;
#else
    Q_UNUSED(ip)
    Q_UNUSED(budget)
    Q_UNUSED(cancelRequested)
    return {};
#endif
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

        if (isPortOpen(ip,
                       def.port,
                       localBindIp,
                       options.serviceTimeoutMs,
                       options.serviceAttempts,
                       budget,
                       cancelRequested)) {
            ServiceHit hit;
            hit.id = def.id;
            hit.label = def.label;
            hit.port = def.port;
            hit.isWeb = def.isWeb;
            hits.append(hit);
        }
    }

    return hits;
}

bool ScannerWindow::isPortOpen(const QString &ip,
                               int port,
                               const QString &localBindIp,
                               int timeoutMs,
                               int attempts,
                               const TargetBudget &budget,
                               const std::shared_ptr<std::atomic_bool> &cancelRequested) const
{
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
            return false;
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
        socket.connectToHost(ip, static_cast<quint16>(port));
        const bool connected = cancellable::waitForConnected(
                                   socket, budget.clampTimeout(timeoutMs), cancelRequested) ==
                               cancellable::WaitResult::Completed;
        socket.abort();
        if (connected) {
            return true;
        }
    }
    return false;
}

QString ScannerWindow::serviceText(const QList<ServiceHit> &services) const
{
    QStringList parts;
    for (const ServiceHit &service : services) {
        parts.append(QString("%1:%2").arg(service.label).arg(service.port));
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
    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    for (int row = 0; row < table_->rowCount(); ++row) {
        QTableWidgetItem *macItem = table_->item(row, ColMac);
        if (macItem == nullptr) {
            continue;
        }
        macItem->setFont(mono);
        const QString formatted = formatMacForDisplay(macItem->text());
        macItem->setText(formatted);
        bool ok = false;
        const qulonglong sortKey = normalizeMacHex12(formatted).toULongLong(&ok, 16);
        macItem->setData(Qt::UserRole, ok ? QVariant(sortKey) : QVariant());
    }
    applyTableColumnSizing();
}

QString ScannerWindow::fetchTcpBanner(const QString &ip, int port, int timeoutMs,
                                      const QString &localBindIp,
                                      const TargetBudget &budget,
                                      const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                      const QByteArray &prologue) const
{
    if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
        return {};
    }
    QTcpSocket socket;
    if (!localBindIp.isEmpty()) {
        QHostAddress bindAddress;
        if (!bindAddress.setAddress(localBindIp) ||
            bindAddress.protocol() != QAbstractSocket::IPv4Protocol ||
            !socket.bind(bindAddress, 0)) {
            return {};
        }
    }
    socket.connectToHost(ip, static_cast<quint16>(port));
    if (cancellable::waitForConnected(
            socket, budget.clampTimeout(timeoutMs), cancelRequested) !=
        cancellable::WaitResult::Completed) {
        return {};
    }
    if (!prologue.isEmpty()) {
        socket.write(prologue);
        if (cancellable::waitForBytesWritten(
                socket, budget.clampTimeout(timeoutMs), cancelRequested) !=
            cancellable::WaitResult::Completed) {
            socket.abort();
            return {};
        }
    }
    if (cancellable::waitForReadyRead(
            socket, budget.clampTimeout(timeoutMs), cancelRequested) !=
        cancellable::WaitResult::Completed) {
        socket.abort();
        return {};
    }
    const QByteArray data = socket.read(4096);
    socket.disconnectFromHost();
    return QString::fromUtf8(data).trimmed();
}

QString ScannerWindow::extractHttpServerHeader(const QString &rawResponse) const
{
    const QStringList lines = rawResponse.split('\n', Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        const QString trimmed = line.trimmed();
        if (trimmed.startsWith("Server:", Qt::CaseInsensitive)) {
            return trimmed.mid(7).trimmed();
        }
    }
    return {};
}

QString ScannerWindow::inferOsFromSignals(const QStringList &signalList) const
{
    const QString blob = signalList.join(" ").toLower();
    if (blob.contains("windows") || blob.contains("microsoft")) {
        return "Likely Windows";
    }
    if (blob.contains("ubuntu") || blob.contains("debian") || blob.contains("centos") ||
        blob.contains("linux") || blob.contains("openssh")) {
        return "Likely Linux/Unix";
    }
    if (blob.contains("cisco") || blob.contains("routeros") || blob.contains("mikrotik")) {
        return "Likely Network Appliance";
    }
    return "Unknown";
}

QString ScannerWindow::collectDeviceDetails(const ScanResult &result,
                                            const QString &localBindIp,
                                            const TargetBudget &budget,
                                            const std::shared_ptr<std::atomic_bool> &cancelRequested,
                                            const ScanOptions &options) const
{
    QStringList lines;
    QStringList signalList;

    lines << QString("IP: %1").arg(result.ip);
    lines << QString("Hostname: %1").arg(result.hostname);
    lines << QString("MAC: %1").arg(formatMacForDisplay(result.mac, options.macDisplayFormat));
    lines << QString("Vendor: %1").arg(result.vendor);
    lines << QString("Services: %1").arg(result.services.isEmpty() ? "None" : serviceText(result.services));

    for (const ServiceHit &service : result.services) {
        if (cancellable::isCancelled(cancelRequested) || budget.expired()) {
            break;
        }
        if (service.id == "http") {
            const QString response = fetchTcpBanner(
                result.ip, 80, options.serviceTimeoutMs, localBindIp, budget, cancelRequested,
                QByteArray("HEAD / HTTP/1.0\r\nHost: " + result.ip.toUtf8() + "\r\n\r\n"));
            const QString server = extractHttpServerHeader(response);
            if (!server.isEmpty()) {
                lines << QString("Web server (80): %1").arg(server);
                signalList << server;
            }
            continue;
        }
        if (service.id == "ssh") {
            const QString banner = fetchTcpBanner(
                result.ip, 22, options.serviceTimeoutMs, localBindIp, budget, cancelRequested);
            if (!banner.isEmpty()) {
                lines << QString("SSH banner: %1").arg(banner.left(180));
                signalList << banner;
            }
            continue;
        }
        if (service.id == "ftp") {
            const QString banner = fetchTcpBanner(
                result.ip, 21, options.serviceTimeoutMs, localBindIp, budget, cancelRequested);
            if (!banner.isEmpty()) {
                lines << QString("FTP banner: %1").arg(banner.left(180));
                signalList << banner;
            }
            continue;
        }
        if (service.id == "telnet") {
            const QString banner = fetchTcpBanner(
                result.ip, 23, options.serviceTimeoutMs, localBindIp, budget, cancelRequested);
            if (!banner.isEmpty()) {
                lines << QString("Telnet banner: %1").arg(banner.left(180));
                signalList << banner;
            }
            continue;
        }
    }

    lines << QString("OS signature: %1").arg(inferOsFromSignals(signalList));
    return lines.join('\n');
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
    const bool sortingEnabled = table_->isSortingEnabled();
    const int sortSectionBefore = table_->horizontalHeader()->sortIndicatorSection();
    const Qt::SortOrder sortOrderBefore = table_->horizontalHeader()->sortIndicatorOrder();
    const QString selectedIdentityBefore = rowIdentityKey(table_->currentRow());
    const int selectedColBefore = std::max(0, table_->currentColumn());
    table_->setUpdatesEnabled(false);
    if (sortingEnabled) {
        table_->setSortingEnabled(false);
    }

    // Rebuild from final authoritative results to avoid UI race/drift from incremental updates.
    table_->setRowCount(0);
    servicesByIdentity_.clear();
    detailsByIdentity_.clear();
    for (const ScanResult &result : finalResults) {
        addOrUpdateResultRow(result);
    }

    if (sortingEnabled) {
        int section = sortSectionBefore;
        Qt::SortOrder order = sortOrderBefore;
        if (section < 0) {
            section = ColIp;
            order = Qt::AscendingOrder;
        }
        table_->setSortingEnabled(true);
        table_->horizontalHeader()->setSortIndicator(section, order);
        table_->sortItems(section, order);
    }
    if (!selectedIdentityBefore.isEmpty()) {
        const int selectedRow = findRowByIdentity(selectedIdentityBefore);
        if (selectedRow >= 0) {
            table_->setCurrentCell(selectedRow, selectedColBefore);
        }
    }
    table_->setUpdatesEnabled(true);
    applyTableFilters();
    applyTableColumnSizing();
    updateDetailsPaneForCurrentSelection();

    scanInProgress_ = false;
    scanButton_->setToolTip("Start scan");
    applyToolbarDisplayMode();
    scanButton_->setEnabled(!adapters_.isEmpty());
    refreshAdaptersButton_->setEnabled(true);
    defaultsButton_->setEnabled(!defaultTargetText_.isEmpty());
    adapterCombo_->setEnabled(true);
    targetInput_->setEnabled(true);

    statusProgressBar_->setVisible(false);

    if (table_->rowCount() == 0) {
        showStatusMessage(wasCanceled
                              ? "Scan stopped. No responding hosts detected."
                              : "Scan complete. No responding hosts detected.");
    } else {
        showStatusMessage(wasCanceled
                              ? QString("Scan stopped. %1 host(s) detected.").arg(table_->rowCount())
                              : QString("Scan complete. %1 host(s) detected.").arg(table_->rowCount()));
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

    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    const QString hostnameText = result.hostname.isEmpty() ? QString("Unknown") : result.hostname;
    const QString macText = formatMacForDisplay(result.mac);
    const QString vendorText = result.vendor.isEmpty() ? QString("Unknown") : result.vendor;
    const QString identityKey = neighborIdentityKey(result.interfaceName, result.ip);
    const qulonglong ipSortKey = static_cast<qulonglong>(ipv4ToInt(QHostAddress(result.ip)));
    qulonglong macSortKey = 0;
    bool hasMacSortKey = false;
    const QString macHex = normalizeMacHex12(result.mac);
    if (!macHex.isEmpty()) {
        macSortKey = macHex.toULongLong(&hasMacSortKey, 16);
    }
    if (!result.services.isEmpty() || !servicesByIdentity_.contains(identityKey)) {
        servicesByIdentity_[identityKey] = result.services;
    }
    if (!result.detailsText.isEmpty() || !detailsByIdentity_.contains(identityKey)) {
        detailsByIdentity_[identityKey] = result.detailsText;
    }

    // Temporarily disable sorting while mutating rows to keep row lookup stable.
    const bool sortingEnabled = table_->isSortingEnabled();
    int sortColumn = table_->horizontalHeader()->sortIndicatorSection();
    Qt::SortOrder sortOrder = table_->horizontalHeader()->sortIndicatorOrder();
    if (sortColumn < 0) {
        sortColumn = ColIp;
        sortOrder = Qt::AscendingOrder;
    }
    if (sortingEnabled) {
        table_->setSortingEnabled(false);
    }
    const int selectedRow = table_->currentRow();
    const int selectedColumn = std::max(0, table_->currentColumn());
    const QString selectedIdentity = rowIdentityKey(selectedRow);

    const int existingRow = findRowByIdentity(identityKey);
    if (existingRow >= 0) {
        const int row = existingRow;

        QTableWidgetItem *hostItem = table_->item(row, ColHostname);
        QTableWidgetItem *macItem = table_->item(row, ColMac);
        QTableWidgetItem *vendorItem = table_->item(row, ColVendor);
        QTableWidgetItem *svcItem = table_->item(row, ColServices);
        QTableWidgetItem *ipItem = table_->item(row, ColIp);

        if (ipItem == nullptr) {
            ipItem = new SortKeyTableWidgetItem(result.ip);
            ipItem->setFont(mono);
            table_->setItem(row, ColIp, ipItem);
        }
        if (hostItem == nullptr) {
            hostItem = new QTableWidgetItem;
            table_->setItem(row, ColHostname, hostItem);
        }
        if (macItem == nullptr) {
            macItem = new SortKeyTableWidgetItem;
            macItem->setFont(mono);
            table_->setItem(row, ColMac, macItem);
        }
        if (vendorItem == nullptr) {
            vendorItem = new QTableWidgetItem;
            table_->setItem(row, ColVendor, vendorItem);
        }
        if (svcItem == nullptr) {
            svcItem = new QTableWidgetItem;
            table_->setItem(row, ColServices, svcItem);
        }

        ipItem->setText(result.ip);
        ipItem->setData(Qt::UserRole, ipSortKey);
        ipItem->setData(kIdentityRole, identityKey);
        if ((hostItem->text().isEmpty() || hostItem->text() == "Unknown") && hostnameText != "Unknown") {
            hostItem->setText(hostnameText);
        }
        if ((macItem->text().isEmpty() || macItem->text() == "Unknown") && macText != "Unknown") {
            macItem->setText(macText);
        }
        macItem->setData(Qt::UserRole, hasMacSortKey ? QVariant(macSortKey) : QVariant());
        if ((vendorItem->text().isEmpty() || vendorItem->text() == "Unknown") && vendorText != "Unknown") {
            vendorItem->setText(vendorText);
        }
        svcItem->setText({});
        if (QWidget *oldWidget = table_->cellWidget(row, ColServices)) {
            table_->removeCellWidget(row, ColServices);
            oldWidget->deleteLater();
        }
        const QList<ServiceHit> displayServices = servicesByIdentity_.value(identityKey);
        if (!displayServices.isEmpty()) {
            auto *svcContainer = new QWidget(table_);
            auto *svcLayout = new QHBoxLayout(svcContainer);
            svcLayout->setContentsMargins(2, 0, 2, 0);
            svcLayout->setSpacing(4);
            for (const ServiceHit &service : displayServices) {
                auto *button = new QPushButton(service.label, svcContainer);
                button->setCursor(Qt::PointingHandCursor);
                button->setFocusPolicy(Qt::NoFocus);
                button->setStyleSheet(serviceButtonStyle(mutedServiceColor(service.id)));
                connect(button, &QPushButton::clicked, this, [this, ip = result.ip, service]() {
                    openService(ip, service);
                });
                svcLayout->addWidget(button);
            }
            svcLayout->addStretch(1);
            table_->setCellWidget(row, ColServices, svcContainer);
        }
    } else {
        const int row = table_->rowCount();
        table_->insertRow(row);
        auto *ipItem = new SortKeyTableWidgetItem(result.ip);
        ipItem->setFont(mono);
        ipItem->setData(Qt::UserRole, ipSortKey);
        ipItem->setData(kIdentityRole, identityKey);
        table_->setItem(row, ColIp, ipItem);
        table_->setItem(row, ColHostname, new QTableWidgetItem(hostnameText));
        auto *macItem = new SortKeyTableWidgetItem(macText);
        macItem->setFont(mono);
        macItem->setData(Qt::UserRole, hasMacSortKey ? QVariant(macSortKey) : QVariant());
        table_->setItem(row, ColMac, macItem);
        table_->setItem(row, ColVendor, new QTableWidgetItem(vendorText));
        table_->setItem(row, ColServices, new QTableWidgetItem(QString()));
        const QList<ServiceHit> displayServices = servicesByIdentity_.value(identityKey);
        if (!displayServices.isEmpty()) {
            auto *svcContainer = new QWidget(table_);
            auto *svcLayout = new QHBoxLayout(svcContainer);
            svcLayout->setContentsMargins(2, 0, 2, 0);
            svcLayout->setSpacing(4);
            for (const ServiceHit &service : displayServices) {
                auto *button = new QPushButton(service.label, svcContainer);
                button->setCursor(Qt::PointingHandCursor);
                button->setFocusPolicy(Qt::NoFocus);
                button->setStyleSheet(serviceButtonStyle(mutedServiceColor(service.id)));
                connect(button, &QPushButton::clicked, this, [this, ip = result.ip, service]() {
                    openService(ip, service);
                });
                svcLayout->addWidget(button);
            }
            svcLayout->addStretch(1);
            table_->setCellWidget(row, ColServices, svcContainer);
        }
    }

    if (sortingEnabled) {
        // Restore the user's active sort after row insert/update.
        table_->setSortingEnabled(true);
        table_->horizontalHeader()->setSortIndicator(sortColumn, sortOrder);
        table_->sortItems(sortColumn, sortOrder);
    }
    if (!selectedIdentity.isEmpty()) {
        const int newRow = findRowByIdentity(selectedIdentity);
        if (newRow >= 0) {
            table_->setCurrentCell(newRow, selectedColumn);
        }
    }
    applyTableFilters();
    applyTableColumnSizing();
    updateDetailsPaneForCurrentSelection();
}

void ScannerWindow::handleTableDoubleClick(int row, int column)
{
    if (column != ColServices) {
        return;
    }

    const QString ip = cellText(row, ColIp);
    const QList<ServiceHit> services = servicesByIdentity_.value(rowIdentityKey(row));
    if (services.isEmpty()) {
        return;
    }

    if (services.size() == 1) {
        openService(ip, services.first());
        return;
    }

    QMenu menu(this);
    for (const ServiceHit &service : services) {
        QAction *action = menu.addAction(QString("Open %1 (%2)").arg(service.label).arg(service.port));
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

    table_->setCurrentCell(index.row(), index.column());

    const QString ip = cellText(index.row(), ColIp);
    const QList<ServiceHit> services = servicesByIdentity_.value(rowIdentityKey(index.row()));

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
        QAction *action = menu.addAction(QString("Open %1 (%2)").arg(service.label).arg(service.port));
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
        QTableWidgetItem *headerItem = table_->horizontalHeaderItem(col);
        const QString title = (headerItem != nullptr) ? headerItem->text() : QString("Column %1").arg(col + 1);
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
    const QTableWidgetItem *item = table_->currentItem();
    if (item == nullptr) {
        return;
    }

    copyCellText(item->row(), item->column());
}

void ScannerWindow::applyTableFilters()
{
    for (int row = 0; row < table_->rowCount(); ++row) {
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
    if (column == ColServices) {
        const QTableWidgetItem *ipItem = table_->item(row, ColIp);
        if (ipItem != nullptr) {
            return serviceText(servicesByIdentity_.value(rowIdentityKey(row)));
        }
    }

    const QTableWidgetItem *item = table_->item(row, column);
    if (item == nullptr) {
        return {};
    }
    return item->text();
}

void ScannerWindow::exportCsv()
{
    if (table_->rowCount() == 0) {
        QMessageBox::warning(this, "Export CSV", "Nothing to export. Run a scan first.");
        return;
    }

    const QString path = QFileDialog::getSaveFileName(this, "Export CSV", "scan-results.csv", "CSV Files (*.csv)");
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, "Export CSV", "Could not write CSV file.");
        return;
    }

    QTextStream out(&file);
    const QList<int> columns = visibleColumnsInDisplayOrder();

    QStringList headers;
    for (int col : columns) {
        QTableWidgetItem *headerItem = table_->horizontalHeaderItem(col);
        headers.append(csvEscape(headerItem == nullptr ? QString("Column%1").arg(col) : headerItem->text()));
    }
    out << headers.join(',') << '\n';

    for (int row = 0; row < table_->rowCount(); ++row) {
        QStringList fields;
        for (int col : columns) {
            fields.append(csvEscape(cellText(row, col)));
        }
        out << fields.join(',') << '\n';
    }

    showStatusMessage(QString("Exported CSV to %1").arg(path));
}

void ScannerWindow::printTable()
{
    if (table_->rowCount() == 0) {
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
        QTableWidgetItem *header = table_->horizontalHeaderItem(col);
        html += QString("<th>%1</th>").arg((header ? header->text() : QString("Column%1").arg(col)).toHtmlEscaped());
    }
    html += "</tr>";

    for (int row = 0; row < table_->rowCount(); ++row) {
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
    connect(defaultsButton, &QPushButton::clicked, &dialog, [availableList, currentList, allIds, addToolbarItem]() {
        availableList->clear();
        currentList->clear();
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

    enabledServiceIds_.clear();
    for (const ServiceDefinition &def : availableServices()) {
        if (serviceChecks.contains(def.id) && serviceChecks[def.id]->isChecked()) {
            enabledServiceIds_.insert(def.id);
        }
    }

    for (auto it = commandEdits.begin(); it != commandEdits.end(); ++it) {
        const QString command = it.value()->text().trimmed();
        if (!command.isEmpty() && !isSafeTextInput(command, 512)) {
            QMessageBox::warning(this, "Settings", QString("Invalid command for service '%1'.").arg(it.key()));
            return;
        }
        customCommands_[it.key()] = command;
    }

    customOuiVendors_.clear();
    const QStringList customOuiLines = ouiEdit->toPlainText().split('\n', Qt::SkipEmptyParts);
    for (const QString &lineRaw : customOuiLines) {
        const QString line = lineRaw.trimmed();
        if (line.isEmpty() || line.startsWith('#')) {
            continue;
        }
        if (!isSafeTextInput(line, 256)) {
            continue;
        }
        const int sep = line.indexOf('=');
        if (sep <= 0) {
            continue;
        }
        const QString prefix = normalizeOuiPrefix(line.left(sep).trimmed());
        const QString vendor = line.mid(sep + 1).trimmed();
        if (!prefix.isEmpty() && !vendor.isEmpty()) {
            customOuiVendors_.insert(prefix, vendor);
        }
    }

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

    applyTableColumnSizing();
    saveSettings();
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
        "Balanced through Maximum progressively repeat ping and port probes and wait longer "
        "for intermittent, sleeping, or slower devices.</p>"
        "<p><b>Services:</b> Enable/disable per-port probing and configure launch commands in "
        "Settings &rarr; Programs.</p>"
        "<p><b>Filtering:</b> Use Find to filter by IP, hostname, MAC, vendor, services, or OUI prefix.</p>"
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
    options.pingAttempts = budget.pingAttempts;
    options.pingTimeoutSeconds = budget.pingTimeoutSeconds;
    options.serviceAttempts = budget.serviceAttempts;
    options.serviceTimeoutMs = budget.serviceTimeoutMs;
    options.macDisplayFormat = macDisplayFormat_;
    options.enabledServiceIds = enabledServiceIds_;
    options.targetDeadlineMs =
        targetDeadlineForProfile(budget, options.enabledServiceIds.size());
    options.builtInOuiVendors = builtInOuiVendors_;
    options.customOuiVendors = customOuiVendors_;
    return options;
}

void ScannerWindow::applyDefaultSettings()
{
    maxParallelProbes_ = 4;
    accuracyLevel_ = 1;
    rememberLastTargetOnLaunch_ = false;
    pendingLastTarget_.clear();
    toolbarDisplayMode_ = 0;
    macDisplayFormat_ = MacColonUpper;
    toolbarItemDisplayModes_.clear();
    toolbarItemDisplayModes_.insert("scan", 0);
    toolbarItemDisplayModes_.insert("auto", 0);
    toolbarItemDisplayModes_.insert("find", 0);
    toolbarItemDisplayModes_.insert("terminal", 0);
    toolbarItemDisplayModes_.insert("refresh", 0);
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

void ScannerWindow::loadSettings()
{
    QSettings settings("OpenIPScanner", "OpenIPScanner");
    const int schema = settings.value("settings/schema_version", -1).toInt();

    if (schema != kSettingsSchemaVersion) {
        settings.clear();
        applyDefaultSettings();
        saveSettings();
        return;
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
    rememberLastTargetOnLaunch_ = settings.value("targets/remember_last", false).toBool();
    pendingLastTarget_.clear();
    if (rememberLastTargetAction_ != nullptr) {
        const QSignalBlocker blocker(rememberLastTargetAction_);
        rememberLastTargetAction_->setChecked(rememberLastTargetOnLaunch_);
    }
    toolbarDisplayMode_ = std::clamp(settings.value("toolbar/display_mode", 0).toInt(), 0, 2);
    macDisplayFormat_ = std::clamp(settings.value("appearance/mac_display_format", static_cast<int>(MacColonUpper)).toInt(),
                                   static_cast<int>(MacColonUpper),
                                   static_cast<int>(MacPlainLower));
    toolbarItemDisplayModes_.clear();
    for (const QString &id : kToolbarButtonIds) {
        const QString key = QString("toolbar/item_mode_%1").arg(id);
        const int fallback = (id == "find") ? 0 : toolbarDisplayMode_;
        const int value = settings.contains(key) ? settings.value(key).toInt() : fallback;
        toolbarItemDisplayModes_.insert(id, std::clamp(value, 0, 2));
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

    const QStringList enabledServices = settings.value("services/enabled_ids").toStringList();
    if (!enabledServices.isEmpty()) {
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
    const QStringList history = settings.value("targets/history").toStringList();
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
        settings.setValue(QString("toolbar/item_mode_%1").arg(id), toolbarItemDisplayModes_.value(id, toolbarDisplayMode_));
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
    settings.setValue("targets/history", targetHistory_);
    settings.setValue("targets/remember_last", rememberLastTargetOnLaunch_);
    settings.setValue("targets/last_input", targetInput_->text().trimmed());

    settings.beginWriteArray("oui/custom_entries");
    int index = 0;
    for (auto it = customOuiVendors_.begin(); it != customOuiVendors_.end(); ++it, ++index) {
        settings.setArrayIndex(index);
        settings.setValue("prefix", it.key());
        settings.setValue("vendor", it.value());
    }
    settings.endArray();
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

void ScannerWindow::recordTargetHistory(const QString &text)
{
    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty() || !isSafeTextInput(trimmed, 2048)) {
        return;
    }

    targetHistory_.removeAll(trimmed);
    targetHistory_.prepend(trimmed);
    while (targetHistory_.size() > 30) {
        targetHistory_.removeLast();
    }
    targetHistoryModel_->setStringList(targetHistory_);
    saveSettings();
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
        return std::clamp(toolbarItemDisplayModes_.value(id, toolbarDisplayMode_), 0, 2);
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
    if (row < 0) {
        return {};
    }
    const QTableWidgetItem *item = table_->item(row, ColIp);
    return item == nullptr ? QString() : item->data(kIdentityRole).toString();
}

int ScannerWindow::findRowByIdentity(const QString &identityKey) const
{
    for (int row = 0; row < table_->rowCount(); ++row) {
        if (rowIdentityKey(row) == identityKey) {
            return row;
        }
    }
    return -1;
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

    const QTableWidgetItem *item = table_->currentItem();
    if (item == nullptr) {
        detailsPane_->setPlainText("Select a device to view details.");
        return;
    }

    const QString details = detailsByIdentity_.value(rowIdentityKey(item->row()));
    if (details.trimmed().isEmpty()) {
        detailsPane_->setPlainText("No details available for selected device.");
        return;
    }
    detailsPane_->setPlainText(details);
}

void ScannerWindow::applyTableColumnSizing()
{
    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    const QFontMetrics monoMetrics(mono);

    const int ipWidth = monoMetrics.horizontalAdvance("255.255.255.255") + 28;
    const int macWidth = monoMetrics.horizontalAdvance("AA:BB:CC:DD:EE:FF") + 28;

    table_->setColumnWidth(ColIp, std::max(table_->columnWidth(ColIp), ipWidth));
    table_->setColumnWidth(ColMac, std::max(table_->columnWidth(ColMac), macWidth));
    table_->resizeColumnToContents(ColIp);
    table_->resizeColumnToContents(ColMac);
    table_->resizeColumnToContents(ColVendor);

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

QString ScannerWindow::csvEscape(const QString &text)
{
    QString escaped = text;
    escaped.replace('"', "\"\"");
    return QString("\"%1\"").arg(escaped);
}

QString ScannerWindow::normalizeOuiPrefix(const QString &prefix)
{
    // Normalize MAC/OUI input to uppercase hex and return the first 24 bits.
    QString normalized = prefix.toUpper();
    normalized.remove(':');
    normalized.remove('-');
    normalized.remove('.');
    if (normalized.size() < 6) {
        return {};
    }
    return normalized.left(6);
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

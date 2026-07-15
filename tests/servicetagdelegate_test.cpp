#include "resulttablemodel.h"
#include "servicetagdelegate.h"

#include <QApplication>
#include <QFont>
#include <QHeaderView>
#include <QImage>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QStyle>
#include <QStyleOptionViewItem>
#include <QTableView>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

struct ServiceTagDelegateTestAccess {
    static QColor foreground(const QPalette &palette,
                             QPalette::ColorGroup group,
                             bool selected,
                             bool alternate,
                             const QString &kind)
    {
        return ServiceTagDelegate::tagColors(
                   palette, group, selected, alternate, kind)
            .foreground;
    }

    static QColor background(const QPalette &palette,
                             QPalette::ColorGroup group,
                             bool selected,
                             bool alternate,
                             const QString &kind)
    {
        return ServiceTagDelegate::tagColors(
                   palette, group, selected, alternate, kind)
            .background;
    }

    static QList<QRect> rects(const ServiceTagDelegate &delegate,
                              const QStyleOptionViewItem &option,
                              const QStringList &tags)
    {
        return delegate.tagRects(option, tags);
    }
};

namespace {

void requireAt(bool condition, int line)
{
    if (!condition) {
        std::fprintf(stderr, "service tag theme requirement failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) requireAt((condition), __LINE__)

double linearChannel(int channel)
{
    const double value = channel / 255.0;
    return value <= 0.04045 ? value / 12.92
                            : std::pow((value + 0.055) / 1.055, 2.4);
}

double luminance(const QColor &color)
{
    return 0.2126 * linearChannel(color.red()) +
           0.7152 * linearChannel(color.green()) +
           0.0722 * linearChannel(color.blue());
}

double contrast(const QColor &left, const QColor &right)
{
    const double lighter = std::max(luminance(left), luminance(right));
    const double darker = std::min(luminance(left), luminance(right));
    return (lighter + 0.05) / (darker + 0.05);
}

QPalette lightPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Base, QColor("#ffffff"));
    palette.setColor(QPalette::AlternateBase, QColor("#f2f2f2"));
    palette.setColor(QPalette::Text, QColor("#111111"));
    palette.setColor(QPalette::WindowText, QColor("#111111"));
    palette.setColor(QPalette::ButtonText, QColor("#111111"));
    palette.setColor(QPalette::Highlight, QColor("#0067c0"));
    palette.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    palette.setColor(QPalette::BrightText, QColor("#ffffff"));
    palette.setColor(QPalette::Disabled, QPalette::Base, QColor("#f0f0f0"));
    palette.setColor(QPalette::Disabled, QPalette::AlternateBase,
                     QColor("#e6e6e6"));
    palette.setColor(QPalette::Disabled, QPalette::Text, QColor("#4a4a4a"));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor("#4a4a4a"));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor("#4a4a4a"));
    palette.setColor(QPalette::Disabled, QPalette::Highlight, QColor("#6c6c6c"));
    palette.setColor(QPalette::Disabled, QPalette::HighlightedText,
                     QColor("#ffffff"));
    palette.setColor(QPalette::Disabled, QPalette::BrightText, QColor("#ffffff"));
    return palette;
}

QPalette darkPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Base, QColor("#202124"));
    palette.setColor(QPalette::AlternateBase, QColor("#292a2d"));
    palette.setColor(QPalette::Text, QColor("#f2f2f2"));
    palette.setColor(QPalette::WindowText, QColor("#f2f2f2"));
    palette.setColor(QPalette::ButtonText, QColor("#f2f2f2"));
    palette.setColor(QPalette::Highlight, QColor("#264f78"));
    palette.setColor(QPalette::HighlightedText, QColor("#ffffff"));
    palette.setColor(QPalette::BrightText, QColor("#ffffff"));
    palette.setColor(QPalette::Disabled, QPalette::Base, QColor("#181818"));
    palette.setColor(QPalette::Disabled, QPalette::AlternateBase,
                     QColor("#222222"));
    palette.setColor(QPalette::Disabled, QPalette::Text, QColor("#c8c8c8"));
    palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor("#c8c8c8"));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor("#c8c8c8"));
    palette.setColor(QPalette::Disabled, QPalette::Highlight, QColor("#303030"));
    palette.setColor(QPalette::Disabled, QPalette::HighlightedText,
                     QColor("#ffffff"));
    palette.setColor(QPalette::Disabled, QPalette::BrightText, QColor("#ffffff"));
    return palette;
}

QPalette highContrastPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Base, Qt::black);
    palette.setColor(QPalette::AlternateBase, Qt::black);
    palette.setColor(QPalette::Text, Qt::white);
    palette.setColor(QPalette::WindowText, Qt::white);
    palette.setColor(QPalette::ButtonText, Qt::white);
    palette.setColor(QPalette::Highlight, Qt::white);
    palette.setColor(QPalette::HighlightedText, Qt::black);
    palette.setColor(QPalette::BrightText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::Base, Qt::black);
    palette.setColor(QPalette::Disabled, QPalette::AlternateBase, Qt::black);
    palette.setColor(QPalette::Disabled, QPalette::Text, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::WindowText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::Highlight, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::HighlightedText, Qt::black);
    palette.setColor(QPalette::Disabled, QPalette::BrightText, Qt::white);
    return palette;
}

void verifyContrast(const QPalette &palette,
                    QPalette::ColorGroup group,
                    bool selected,
                    bool alternate)
{
    const QColor surface = palette.color(
        group,
        selected ? QPalette::Highlight
                 : (alternate ? QPalette::AlternateBase : QPalette::Base));
    for (const QString &kind : {QString(), QString("http"), QString("ssh"),
                                QString("rdp"), QString("ftp"),
                                QString("smtp25")}) {
        const QColor foreground = ServiceTagDelegateTestAccess::foreground(
            palette, group, selected, alternate, kind);
        const QColor background = ServiceTagDelegateTestAccess::background(
            palette, group, selected, alternate, kind);
        if (contrast(foreground, background) < 4.5) {
            std::fprintf(stderr,
                         "text contrast %.3f kind=%s group=%d selected=%d "
                         "text=%s fill=%s\n",
                         contrast(foreground, background),
                         kind.toUtf8().constData(),
                         static_cast<int>(group),
                         selected,
                         foreground.name().toUtf8().constData(),
                         background.name().toUtf8().constData());
        }
        REQUIRE(contrast(foreground, background) >= 4.5);
        if (contrast(background, surface) < 3.0) {
            std::fprintf(stderr,
                         "fill contrast %.3f kind=%s group=%d selected=%d "
                         "fill=%s surface=%s\n",
                         contrast(background, surface),
                         kind.toUtf8().constData(),
                         static_cast<int>(group),
                         selected,
                         background.name().toUtf8().constData(),
                         surface.name().toUtf8().constData());
        }
        REQUIRE(contrast(background, surface) >= 3.0);
        if (kind.isEmpty()) {
            REQUIRE(background.hslSaturation() == 0);
        } else {
            REQUIRE(background.hslSaturation() > 0);
        }
    }
}

} // namespace

int main(int argc, char **argv)
{
    QApplication application(argc, argv);

    for (const QPalette &palette :
         {lightPalette(), darkPalette(), highContrastPalette()}) {
        for (const QPalette::ColorGroup group :
             {QPalette::Active, QPalette::Inactive, QPalette::Disabled}) {
            verifyContrast(palette, group, false, false);
            verifyContrast(palette, group, false, true);
            verifyContrast(palette, group, true, false);
        }
    }

    const QPalette palette = lightPalette();
    const QColor web = ServiceTagDelegateTestAccess::background(
        palette, QPalette::Active, false, false, "http");
    const QColor remote = ServiceTagDelegateTestAccess::background(
        palette, QPalette::Active, false, false, "ssh");
    const QColor desktop = ServiceTagDelegateTestAccess::background(
        palette, QPalette::Active, false, false, "rdp");
    const QColor file = ServiceTagDelegateTestAccess::background(
        palette, QPalette::Active, false, false, "ftp");
    const QColor mail = ServiceTagDelegateTestAccess::background(
        palette, QPalette::Active, false, false, "smtp25");
    REQUIRE(web != remote);
    REQUIRE(web != desktop);
    REQUIRE(web != file);
    REQUIRE(web != mail);
    REQUIRE(remote != desktop);
    REQUIRE(desktop != file);
    REQUIRE(file != mail);
    REQUIRE(ServiceTagDelegateTestAccess::background(
                palette, QPalette::Active, false, false, "https") == web);
    REQUIRE(ServiceTagDelegateTestAccess::background(
                palette, QPalette::Active, false, false, "telnet") == remote);
    REQUIRE(ServiceTagDelegateTestAccess::background(
                palette, QPalette::Active, false, false, "smb") == file);
    REQUIRE(ServiceTagDelegateTestAccess::background(
                palette, QPalette::Active, false, false, "smtps465") == mail);

    ResultTableModel model;
    ScanResult result;
    result.ip = "192.0.2.10";
    result.services = {
        {"ssh", "SSH", 22, false, ServiceEvidenceLevel::VerifiedProtocol},
        {"http", "HTTP", 80, true, ServiceEvidenceLevel::OpenPort},
    };
    REQUIRE(model.upsertResult(result));
    const QModelIndex serviceIndex = model.index(0, ResultTableModel::Services);
    REQUIRE(serviceIndex.data(ResultTableModel::ServiceTagsRole).toStringList() ==
            QStringList({"SSH:22", "Unknown:80"}));
    REQUIRE(serviceIndex.data(ResultTableModel::ServiceKindsRole).toStringList() ==
            QStringList({"ssh", ""}));

    ServiceTagDelegate delegate;
    QStyleOptionViewItem option;
    option.rect = QRect(0, 0, 500, 32);
    option.font = application.font();
    option.palette = lightPalette();
    option.state = QStyle::State_Enabled | QStyle::State_Active;
    const QStringList tags = {"SSH:22", "Unknown:80", "HTTPS:443"};
    const QList<QRect> baseline =
        ServiceTagDelegateTestAccess::rects(delegate, option, tags);
    REQUIRE(baseline.size() == tags.size());
    for (const QPalette &statePalette :
         {lightPalette(), darkPalette(), highContrastPalette()}) {
        option.palette = statePalette;
        const QList<QStyle::State> states = {
            QStyle::State(QStyle::State_Enabled | QStyle::State_Active),
            QStyle::State(QStyle::State_Enabled | QStyle::State_Active |
                          QStyle::State_Selected),
            QStyle::State(QStyle::State_Enabled),
            QStyle::State(QStyle::State_None),
            QStyle::State(QStyle::State_Selected),
        };
        for (const QStyle::State state : states) {
            option.state = state;
            REQUIRE(ServiceTagDelegateTestAccess::rects(delegate, option, tags) ==
                    baseline);
        }
    }

    const QList<QRect> renderedRects =
        ServiceTagDelegateTestAccess::rects(delegate, option,
            serviceIndex.data(ResultTableModel::ServiceTagsRole).toStringList());
    REQUIRE(renderedRects.size() == 2);
    struct PaintCase {
        QStyle::State state;
        QPalette::ColorGroup group;
        bool selected;
        bool alternate;
    };
    const QList<PaintCase> paintCases = {
        {QStyle::State(QStyle::State_Enabled | QStyle::State_Active),
         QPalette::Active, false, false},
        {QStyle::State(QStyle::State_Enabled | QStyle::State_Active |
                       QStyle::State_Selected),
         QPalette::Active, true, false},
        {QStyle::State(QStyle::State_Enabled),
         QPalette::Inactive, false, true},
        {QStyle::State(QStyle::State_None),
         QPalette::Disabled, false, false},
    };
    option.palette = highContrastPalette();
    for (const PaintCase &paintCase : paintCases) {
        option.state = paintCase.state;
        option.features.setFlag(QStyleOptionViewItem::Alternate,
                                paintCase.alternate);
        QImage rendered(option.rect.size(), QImage::Format_ARGB32_Premultiplied);
        rendered.fill(Qt::transparent);
        {
            QPainter painter(&rendered);
            delegate.paint(&painter, option, serviceIndex);
        }
        const QColor expectedVerified = ServiceTagDelegateTestAccess::background(
            option.palette, paintCase.group, paintCase.selected,
            paintCase.alternate, "ssh");
        const QColor expectedUnknown = ServiceTagDelegateTestAccess::background(
            option.palette, paintCase.group, paintCase.selected,
            paintCase.alternate, QString());
        const QColor paintedVerified = rendered.pixelColor(
            renderedRects.at(0).center().x(), renderedRects.at(0).top() + 4);
        const QColor paintedUnknown = rendered.pixelColor(
            renderedRects.at(1).center().x(), renderedRects.at(1).top() + 4);
        REQUIRE(paintedVerified.rgba() == expectedVerified.rgba());
        REQUIRE(paintedUnknown.rgba() == expectedUnknown.rgba());
    }

    int activatedIndex = -1;
    QObject::connect(&delegate, &ServiceTagDelegate::serviceActivated,
                     [&activatedIndex](const QModelIndex &, int serviceIndexValue) {
                         activatedIndex = serviceIndexValue;
                     });
    option.state = QStyle::State_Enabled | QStyle::State_Active;
    option.features.setFlag(QStyleOptionViewItem::Alternate, false);
    const QPoint secondCenter = renderedRects.at(1).center();
    QMouseEvent click(QEvent::MouseButtonRelease,
                      QPointF(secondCenter),
                      QPointF(secondCenter),
                      Qt::LeftButton,
                      Qt::LeftButton,
                      Qt::NoModifier);
    REQUIRE(delegate.editorEvent(&click, &model, option, serviceIndex));
    REQUIRE(activatedIndex == 1);
    const QSize baselineHint = delegate.sizeHint(option, serviceIndex);
    REQUIRE(baselineHint.height() >= option.fontMetrics.height() + 10);
    option.palette = darkPalette();
    option.state = QStyle::State_Enabled;
    option.features.setFlag(QStyleOptionViewItem::Alternate, true);
    REQUIRE(delegate.sizeHint(option, serviceIndex) == baselineHint);

    QTableView view;
    view.setModel(&model);
    auto *hoverDelegate = new ServiceTagDelegate(&view);
    view.setItemDelegateForColumn(ResultTableModel::Services, hoverDelegate);
    view.resize(720, 120);
    for (int column = 0; column < ResultTableModel::ColumnCount; ++column) {
        view.setColumnWidth(column, column == ResultTableModel::Services ? 300 : 80);
    }
    view.doItemsLayout();
    const QRect serviceCell = view.visualRect(serviceIndex);
    QStyleOptionViewItem hoverOption;
    hoverOption.initFrom(view.viewport());
    hoverOption.rect = serviceCell;
    hoverOption.font = view.font();
    const QList<QRect> hoverRects = ServiceTagDelegateTestAccess::rects(
        *hoverDelegate,
        hoverOption,
        serviceIndex.data(ResultTableModel::ServiceTagsRole).toStringList());
    REQUIRE(hoverRects.size() == 2);

    const QPoint hoverPoint = hoverRects.first().center();
    QMouseEvent hoverMove(QEvent::MouseMove,
                          QPointF(hoverPoint),
                          QPointF(hoverPoint),
                          Qt::NoButton,
                          Qt::NoButton,
                          Qt::NoModifier);
    QApplication::sendEvent(view.viewport(), &hoverMove);
    REQUIRE(view.viewport()->cursor().shape() == Qt::PointingHandCursor);

    const QPoint plainPoint = view.visualRect(model.index(0, 0)).center();
    QMouseEvent plainMove(QEvent::MouseMove,
                          QPointF(plainPoint),
                          QPointF(plainPoint),
                          Qt::NoButton,
                          Qt::NoButton,
                          Qt::NoModifier);
    QApplication::sendEvent(view.viewport(), &plainMove);
    REQUIRE(view.viewport()->cursor().shape() != Qt::PointingHandCursor);
    QEvent leave(QEvent::Leave);
    QApplication::sendEvent(view.viewport(), &leave);
    REQUIRE(view.viewport()->cursor().shape() != Qt::PointingHandCursor);

    return EXIT_SUCCESS;
}

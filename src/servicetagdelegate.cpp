#include "servicetagdelegate.h"

#include "resulttablemodel.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QMouseEvent>
#include <QPainter>

#include <algorithm>
#include <cmath>

namespace {

double linearChannel(int channel)
{
    const double value = channel / 255.0;
    return value <= 0.04045 ? value / 12.92
                            : std::pow((value + 0.055) / 1.055, 2.4);
}

double relativeLuminance(const QColor &color)
{
    return 0.2126 * linearChannel(color.red()) +
           0.7152 * linearChannel(color.green()) +
           0.0722 * linearChannel(color.blue());
}

double contrastRatio(const QColor &left, const QColor &right)
{
    const double light = std::max(relativeLuminance(left), relativeLuminance(right));
    const double dark = std::min(relativeLuminance(left), relativeLuminance(right));
    return (light + 0.05) / (dark + 0.05);
}

int serviceHue(const QString &serviceKind)
{
    if (serviceKind == "http" || serviceKind == "https") {
        return 210;
    }
    if (serviceKind == "ssh" || serviceKind == "telnet") {
        return 145;
    }
    if (serviceKind == "rdp") {
        return 275;
    }
    if (serviceKind == "ftp" || serviceKind == "smb") {
        return 32;
    }
    if (serviceKind.startsWith("smtp")) {
        return 345;
    }
    return 185;
}

QColor bestTextColor(const QPalette &palette,
                     QPalette::ColorGroup group,
                     const QColor &background)
{
    const QList<QColor> candidates = {
        palette.color(group, QPalette::Text),
        palette.color(group, QPalette::WindowText),
        palette.color(group, QPalette::ButtonText),
        palette.color(group, QPalette::HighlightedText),
        palette.color(group, QPalette::BrightText),
        palette.color(group, QPalette::Base),
        palette.color(group, QPalette::Window),
        palette.color(group, QPalette::Highlight),
    };
    QColor best = candidates.first();
    double bestContrast = contrastRatio(best, background);
    for (const QColor &candidate : candidates) {
        const double candidateContrast = contrastRatio(candidate, background);
        if (candidateContrast > bestContrast) {
            best = candidate;
            bestContrast = candidateContrast;
        }
    }
    return best;
}

} // namespace

ServiceTagDelegate::ServiceTagDelegate(QAbstractItemView *view)
    : QStyledItemDelegate(view), view_(view)
{
    if (view_ != nullptr) {
        view_->setMouseTracking(true);
        viewport_ = view_->viewport();
        viewport_->installEventFilter(this);
    }
}

ServiceTagDelegate::TagColors ServiceTagDelegate::tagColors(
    const QPalette &palette,
    QPalette::ColorGroup group,
    bool selected,
    bool alternate,
    const QString &serviceKind)
{
    const QColor surface = palette.color(
        group,
        selected ? QPalette::Highlight
                 : (alternate ? QPalette::AlternateBase : QPalette::Base));
    const bool verified = !serviceKind.isEmpty();
    const int saturation = verified ? 165 : 0;
    const int hue = verified ? serviceHue(serviceKind) : 0;
    const QColor darkBackground = QColor::fromHsl(hue, saturation, 52);
    const QColor lightBackground = QColor::fromHsl(hue, saturation, 215);
    const QColor background =
        contrastRatio(darkBackground, surface) >=
                contrastRatio(lightBackground, surface)
            ? darkBackground
            : lightBackground;
    const QColor foreground = bestTextColor(palette, group, background);
    return {foreground, background, foreground};
}

QList<QRect> ServiceTagDelegate::tagRects(const QStyleOptionViewItem &option,
                                          const QStringList &tags) const
{
    QList<QRect> rects;
    const QFontMetrics metrics(option.font);
    int x = option.rect.left() + 4;
    const int height = std::min(option.rect.height() - 4, metrics.height() + 6);
    const int y = option.rect.center().y() - height / 2;
    for (const QString &tag : tags) {
        const int width = metrics.horizontalAdvance(tag) + 14;
        if (x + width > option.rect.right() - 2) {
            break;
        }
        rects.append(QRect(x, y, width, height));
        x += width + 4;
    }
    return rects;
}

int ServiceTagDelegate::tagIndexAt(const QStyleOptionViewItem &option,
                                   const QModelIndex &index,
                                   const QPoint &position) const
{
    const QList<QRect> rects = tagRects(
        option, index.data(ResultTableModel::ServiceTagsRole).toStringList());
    for (int tagIndex = 0; tagIndex < rects.size(); ++tagIndex) {
        if (rects.at(tagIndex).contains(position)) {
            return tagIndex;
        }
    }
    return -1;
}

bool ServiceTagDelegate::eventFilter(QObject *watched, QEvent *event)
{
    if (watched != viewport_) {
        return QStyledItemDelegate::eventFilter(watched, event);
    }
    auto *viewport = qobject_cast<QWidget *>(watched);
    if (viewport == nullptr) {
        return false;
    }
    if (event->type() == QEvent::Leave) {
        viewport->unsetCursor();
        return false;
    }
    if (event->type() != QEvent::MouseMove) {
        return false;
    }

    auto *view = qobject_cast<QAbstractItemView *>(view_);
    if (view == nullptr) {
        viewport->unsetCursor();
        return false;
    }

    const auto *mouse = static_cast<QMouseEvent *>(event);
    const QPoint position = mouse->position().toPoint();
    const QModelIndex index = view->indexAt(position);
    bool overTag = false;
    if (index.isValid() && index.column() == ResultTableModel::Services) {
        QStyleOptionViewItem option;
        option.initFrom(viewport);
        option.rect = view->visualRect(index);
        option.font = view->font();
        overTag = tagIndexAt(option, index, position) >= 0;
    }
    if (overTag) {
        viewport->setCursor(Qt::PointingHandCursor);
    } else {
        viewport->unsetCursor();
    }
    return false;
}

void ServiceTagDelegate::paint(QPainter *painter,
                               const QStyleOptionViewItem &option,
                               const QModelIndex &index) const
{
    QStyleOptionViewItem background(option);
    initStyleOption(&background, index);
    background.text.clear();
    const QWidget *widget = option.widget;
    const QStyle *style = widget ? widget->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &background, painter, widget);

    const QStringList tags = index.data(ResultTableModel::ServiceTagsRole).toStringList();
    const QStringList kinds = index.data(ResultTableModel::ServiceKindsRole).toStringList();
    const QList<QRect> rects = tagRects(option, tags);
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    for (int i = 0; i < rects.size(); ++i) {
        const QPalette::ColorGroup group =
            !option.state.testFlag(QStyle::State_Enabled)
                ? QPalette::Disabled
                : (option.state.testFlag(QStyle::State_Active)
                       ? QPalette::Active
                       : QPalette::Inactive);
        const TagColors colors = tagColors(
            option.palette,
            group,
            option.state.testFlag(QStyle::State_Selected),
            option.features.testFlag(QStyleOptionViewItem::Alternate),
            i < kinds.size() ? kinds.at(i) : QString());
        painter->setPen(colors.border);
        painter->setBrush(colors.background);
        painter->drawRoundedRect(rects.at(i), 4, 4);
        painter->setPen(colors.foreground);
        painter->drawText(rects.at(i), Qt::AlignCenter, tags.at(i));
    }
    painter->restore();
}

QSize ServiceTagDelegate::sizeHint(const QStyleOptionViewItem &option,
                                   const QModelIndex &index) const
{
    QSize hint = QStyledItemDelegate::sizeHint(option, index);
    if (!index.data(ResultTableModel::ServiceTagsRole).toStringList().isEmpty()) {
        hint.setHeight(std::max(hint.height(), option.fontMetrics.height() + 10));
    }
    return hint;
}

bool ServiceTagDelegate::editorEvent(QEvent *event,
                                     QAbstractItemModel *model,
                                     const QStyleOptionViewItem &option,
                                     const QModelIndex &index)
{
    Q_UNUSED(model)
    if (event->type() != QEvent::MouseButtonRelease) {
        return false;
    }
    const auto *mouse = static_cast<QMouseEvent *>(event);
    if (mouse->button() != Qt::LeftButton) {
        return false;
    }
    const int tagIndex = tagIndexAt(option, index, mouse->position().toPoint());
    if (tagIndex >= 0) {
        emit serviceActivated(index, tagIndex);
        return true;
    }
    return false;
}

#include "servicetagdelegate.h"

#include "resulttablemodel.h"

#include <QApplication>
#include <QMouseEvent>
#include <QPainter>

ServiceTagDelegate::ServiceTagDelegate(QObject *parent) : QStyledItemDelegate(parent) {}

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
    const QList<QRect> rects = tagRects(option, tags);
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    for (int i = 0; i < rects.size(); ++i) {
        const QColor fill = option.state.testFlag(QStyle::State_Selected)
                                ? QColor("#315f8f")
                                : QColor("#536672");
        painter->setPen(fill.lighter(125));
        painter->setBrush(fill);
        painter->drawRoundedRect(rects.at(i), 4, 4);
        painter->setPen(Qt::white);
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
    const QList<QRect> rects = tagRects(
        option, index.data(ResultTableModel::ServiceTagsRole).toStringList());
    for (int i = 0; i < rects.size(); ++i) {
        if (rects.at(i).contains(mouse->pos())) {
            emit serviceActivated(index, i);
            return true;
        }
    }
    return false;
}

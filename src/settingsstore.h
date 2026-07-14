#pragma once

#include <QString>
#include <QStringList>

class QSettings;

class SettingsStore {
public:
    static constexpr int CurrentSchemaVersion = 3;

    static bool migrate(QSettings &settings, QString *error = nullptr);
    static bool clearRetainedTargets(QSettings &settings,
                                     bool disableRetention,
                                     QString *error = nullptr);
    static bool persistTargetHistory(QSettings &settings,
                                     const QStringList &history,
                                     const QString &lastInput,
                                     bool rememberLast,
                                     QString *error = nullptr);
};

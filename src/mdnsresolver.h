#pragma once

#include "cancellablewait.h"

#include <QString>

#include <functional>
#include <memory>

class QDBusError;

enum class MdnsLookupStatus {
    Resolved,
    NoRecord,
    TimedOut,
    Cancelled,
    BackendUnavailable,
    InvalidResponse
};

struct MdnsLookupResult {
    MdnsLookupStatus status = MdnsLookupStatus::BackendUnavailable;
    QString hostname;
};

struct MdnsBackendReply {
    MdnsLookupStatus status = MdnsLookupStatus::BackendUnavailable;
    int interfaceIndex = -1;
    int lookupProtocol = -1;
    int addressProtocol = -1;
    QString address;
    QString hostname;
};

class MdnsLookupBackend {
public:
    using Callback = std::function<void(const MdnsBackendReply &)>;

    virtual ~MdnsLookupBackend() = default;
    virtual void resolve(int interfaceIndex,
                         const QString &address,
                         int timeoutMs,
                         Callback callback) = 0;
    virtual void cancelAll() = 0;
};

class ScanMdnsResolver {
public:
    ScanMdnsResolver(int interfaceIndex,
                     cancellable::Flag cancellation,
                     std::unique_ptr<MdnsLookupBackend> backend);
    ~ScanMdnsResolver();

    MdnsLookupResult resolve(const QString &address, int timeoutMs);
    void cancel();

private:
    struct SharedState;

    int interfaceIndex_ = -1;
    cancellable::Flag cancellation_;
    std::unique_ptr<MdnsLookupBackend> backend_;
    std::shared_ptr<SharedState> state_;
};

std::unique_ptr<MdnsLookupBackend> createAvahiDbusBackend();
MdnsLookupStatus mdnsStatusForDbusError(const QDBusError &error);

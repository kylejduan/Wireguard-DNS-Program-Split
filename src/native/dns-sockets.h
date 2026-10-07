// SPDX-License-Identifier: GPL-3.0-or-later
// Private nonblocking I/O: deadlines cover the entire operation, including partial transfers.
using Deadline = std::chrono::steady_clock::time_point;

Deadline afterMilliseconds(int milliseconds) {
    return std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
}

struct SocketOwner {
    SOCKET value;
    explicit SocketOwner(SOCKET socketHandle) : value(socketHandle) {}
    ~SocketOwner() { if (value != INVALID_SOCKET) closesocket(value); }
    SocketOwner(const SocketOwner&) = delete;
    SocketOwner& operator=(const SocketOwner&) = delete;
};

bool nonblocking(SOCKET socketHandle) {
    u_long enabled = 1;
    return ioctlsocket(socketHandle, FIONBIO, &enabled) == 0;
}

bool socketReady(SOCKET socketHandle, bool writing, Deadline deadline) {
    while (gRunning) {
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) return false;
        fd_set ready, errors;
        FD_ZERO(&ready);
        FD_ZERO(&errors);
        FD_SET(socketHandle, &ready);
        FD_SET(socketHandle, &errors);
        timeval wait{0, static_cast<long>(std::min<long long>(remaining, 200000))};
        const int result = select(0, writing ? nullptr : &ready, writing ? &ready : nullptr, &errors, &wait);
        if (result == SOCKET_ERROR || FD_ISSET(socketHandle, &errors)) return false;
        if (result > 0) return true;
    }
    return false;
}

bool connectBefore(SOCKET socketHandle, const sockaddr_in& target, Deadline deadline) {
    if (connect(socketHandle, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) == 0) return true;
    if (WSAGetLastError() != WSAEWOULDBLOCK || !socketReady(socketHandle, true, deadline)) return false;
    int error{};
    int length = sizeof(error);
    return getsockopt(socketHandle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == 0 && !error;
}

bool sendAll(SOCKET socketHandle, const char* data, int size, Deadline deadline) {
    int sent{};
    while (sent < size) {
        if (!socketReady(socketHandle, true, deadline)) return false;
        const int current = send(socketHandle, data + sent, size - sent, 0);
        if (current == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (current <= 0) return false;
        sent += current;
    }
    return true;
}

bool receiveAll(SOCKET socketHandle, char* data, int size, Deadline deadline) {
    int received{};
    while (received < size) {
        if (!socketReady(socketHandle, false, deadline)) return false;
        const int current = recv(socketHandle, data + received, size - received, 0);
        if (current == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (current <= 0) return false;
        received += current;
    }
    return true;
}

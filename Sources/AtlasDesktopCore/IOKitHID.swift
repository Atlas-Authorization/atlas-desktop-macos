import Foundation
import IOKit.hid

/// A FIDO HID device (usage page 0xF1D0, usage 0x01) through IOKit. Reports are 64 bytes without a report id.
/// Compiled everywhere; exercised only with a real key (the unit tests use a software transport).
final class IOKitCTAPHIDTransport: CTAPHIDTransport {
    private let device: IOHIDDevice
    private let lock = NSCondition()
    private var queue: [Data] = []
    private var closed = false
    private var buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: CTAPHID.packetSize)
    private var thread: Thread?
    private var runLoop: CFRunLoop?

    private init(_ d: IOHIDDevice) { device = d }

    deinit { buffer.deallocate() }

    /// The keys plugged in right now, opened and listening.
    static func openAll() throws -> [CTAPHIDTransport] {
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        let match: [String: Any] = [kIOHIDDeviceUsagePageKey: CTAPHID.usagePage, kIOHIDDeviceUsageKey: CTAPHID.usage]
        IOHIDManagerSetDeviceMatching(manager, match as CFDictionary)
        guard IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess else { throw CTAPHIDError.noDevice }
        guard let set = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else { return [] }
        return set.compactMap { d in
            let t = IOKitCTAPHIDTransport(d)
            return t.start() ? t : nil
        }
    }

    private func start() -> Bool {
        guard IOHIDDeviceOpen(device, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess else { return false }
        let ready = DispatchSemaphore(value: 0)
        let th = Thread { [unowned self] in
            self.runLoop = CFRunLoopGetCurrent()
            IOHIDDeviceRegisterInputReportCallback(self.device, self.buffer, CTAPHID.packetSize, { ctx, _, _, _, _, report, length in
                let me = Unmanaged<IOKitCTAPHIDTransport>.fromOpaque(ctx!).takeUnretainedValue()
                me.lock.lock(); me.queue.append(Data(bytes: report, count: length)); me.lock.signal(); me.lock.unlock()
            }, Unmanaged.passUnretained(self).toOpaque())
            IOHIDDeviceScheduleWithRunLoop(self.device, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
            ready.signal()
            while !self.closed { CFRunLoopRunInMode(.defaultMode, 0.2, false) }
        }
        th.name = "atlas-ctaphid"; thread = th; th.start()
        _ = ready.wait(timeout: .now() + 2)
        return true
    }

    func write(_ packet: Data) throws {
        guard packet.count == CTAPHID.packetSize else { throw CTAPHIDError.protocolViolation("packet size") }
        let rc = packet.withUnsafeBytes { IOHIDDeviceSetReport(device, kIOHIDReportTypeOutput, 0, $0.bindMemory(to: UInt8.self).baseAddress!, packet.count) }
        guard rc == kIOReturnSuccess else { throw CTAPHIDError.protocolViolation("HID write \(rc)") }
    }

    func read(timeout: TimeInterval) throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        lock.lock(); defer { lock.unlock() }
        while queue.isEmpty {
            if closed { throw CTAPHIDError.noDevice }
            if !lock.wait(until: deadline) { throw CTAPHIDError.timeout }
        }
        return queue.removeFirst()
    }

    func close() {
        lock.lock(); closed = true; lock.broadcast(); lock.unlock()
        IOHIDDeviceUnscheduleFromRunLoop(device, runLoop ?? CFRunLoopGetMain(), CFRunLoopMode.defaultMode.rawValue)
        IOHIDDeviceClose(device, IOOptionBits(kIOHIDOptionsTypeNone))
    }
}

public extension CTAP2Authenticator {
    /// Security keys over USB HID. `pin` is asked when the key needs its PIN (nil = the person cancelled).
    static func usb(pin: @escaping (_ retriesLeft: Int?) async -> String?, status: @escaping (String) -> Void = { _ in }) -> CTAP2Authenticator {
        CTAP2Authenticator(openDevices: { try IOKitCTAPHIDTransport.openAll() }, pin: pin, status: status)
    }
}

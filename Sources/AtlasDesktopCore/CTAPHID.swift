import Foundation

// CTAPHID: the USB HID transport of CTAP2 (FIDO CTAP 2.1, section 11.2, https://fidoalliance.org/specs/fido-v2.1-ps-20210615/).
// Packets are 64 bytes. Initialization packet: CID(4) CMD(1, bit 7 set) BCNTH BCNTL DATA(57). Continuation packet: CID(4)
// SEQ(1, bit 7 clear, 0...127) DATA(59). A message carries at most 57 + 128 * 59 = 7609 bytes.

enum CTAPHID {
    static let packetSize = 64
    static let broadcastCID: UInt32 = 0xFFFF_FFFF
    static let maxPayload = (packetSize - 7) + 128 * (packetSize - 5)
    static let cmdPing: UInt8 = 0x01, cmdMsg: UInt8 = 0x03, cmdInit: UInt8 = 0x06, cmdCBOR: UInt8 = 0x10, cmdCancel: UInt8 = 0x11
    static let cmdKeepalive: UInt8 = 0x3B, cmdError: UInt8 = 0x3F
    static let keepaliveProcessing: UInt8 = 1, keepaliveUPNeeded: UInt8 = 2
    static let capCBOR: UInt8 = 0x04
    /// HID usage page 0xF1D0, usage 0x01.
    static let usagePage = 0xF1D0, usage = 0x01

    static func cidBytes(_ cid: UInt32) -> [UInt8] { (0..<4).map { UInt8((cid >> UInt32(8 * (3 - $0))) & 0xff) } }
    static func cid(_ d: Data, at i: Int = 0) -> UInt32 { (0..<4).reduce(0) { ($0 << 8) | UInt32(d[d.startIndex + i + $1]) } }

    /// One message as 64-byte packets, unused bytes zero.
    static func split(cid: UInt32, cmd: UInt8, payload: Data) -> [Data] {
        precondition(payload.count <= maxPayload)
        var packets: [Data] = []
        var first = Data(cidBytes(cid) + [cmd | 0x80, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
        let head = payload.prefix(packetSize - 7)
        first.append(head); first.append(Data(repeating: 0, count: packetSize - first.count))
        packets.append(first)
        var rest = payload.dropFirst(head.count), seq: UInt8 = 0
        while !rest.isEmpty {
            let chunk = rest.prefix(packetSize - 5)
            var p = Data(cidBytes(cid) + [seq]); p.append(chunk); p.append(Data(repeating: 0, count: packetSize - p.count))
            packets.append(p); rest = rest.dropFirst(chunk.count); seq += 1
        }
        return packets
    }
}

enum CTAPHIDError: Error, Equatable {
    case timeout
    case device(UInt8)          // CTAPHID_ERROR
    case protocolViolation(String)
    case noDevice
    case cancelled
}

struct CTAPHIDMessage: Equatable { var cid: UInt32; var cmd: UInt8; var payload: Data }

/// Puts packets of one channel back together. Packets of other channels are ignored (a key may talk to several clients).
struct CTAPHIDReassembler {
    let cid: UInt32
    private var cmd: UInt8 = 0, expected = 0, nextSeq: UInt8 = 0
    private var buf = Data()
    private var active = false

    init(cid: UInt32) { self.cid = cid }

    mutating func feed(_ packet: Data) throws -> CTAPHIDMessage? {
        guard packet.count == CTAPHID.packetSize else { throw CTAPHIDError.protocolViolation("packet size \(packet.count)") }
        guard CTAPHID.cid(packet) == cid else { return nil }
        let b4 = packet[packet.startIndex + 4]
        if b4 & 0x80 != 0 {                                    // initialization packet
            if active { throw CTAPHIDError.protocolViolation("new message while one is in progress") }
            cmd = b4 & 0x7f
            expected = Int(packet[packet.startIndex + 5]) << 8 | Int(packet[packet.startIndex + 6])
            guard expected <= CTAPHID.maxPayload else { throw CTAPHIDError.protocolViolation("length \(expected)") }
            buf = Data(packet.dropFirst(7).prefix(expected)); nextSeq = 0; active = true
        } else {                                               // continuation packet
            guard active else { throw CTAPHIDError.protocolViolation("continuation without a start") }
            guard b4 == nextSeq else { throw CTAPHIDError.protocolViolation("sequence \(b4), wanted \(nextSeq)") }
            buf.append(packet.dropFirst(5).prefix(expected - buf.count)); nextSeq += 1
        }
        if buf.count == expected {
            active = false
            return CTAPHIDMessage(cid: cid, cmd: cmd, payload: buf)
        }
        return nil
    }
}

/// A HID device that speaks 64-byte reports. IOKit in production, a software authenticator in tests.
protocol CTAPHIDTransport: AnyObject {
    func write(_ packet: Data) throws
    /// Blocks up to `timeout` seconds; throws `.timeout` when nothing arrived.
    func read(timeout: TimeInterval) throws -> Data
    func close()
}

/// One allocated channel to one key.
final class CTAPHIDChannel {
    let transport: CTAPHIDTransport
    private(set) var cid: UInt32 = CTAPHID.broadcastCID
    private(set) var capabilities: UInt8 = 0

    init(_ t: CTAPHIDTransport) { transport = t }

    /// CTAPHID_INIT on the broadcast channel; a response that does not echo our nonce belongs to someone else and is skipped.
    func open(timeout: TimeInterval = 3) throws {
        let nonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        for p in CTAPHID.split(cid: CTAPHID.broadcastCID, cmd: CTAPHID.cmdInit, payload: nonce) { try transport.write(p) }
        var r = CTAPHIDReassembler(cid: CTAPHID.broadcastCID)
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { throw CTAPHIDError.timeout }
            guard let m = try r.feed(try transport.read(timeout: left)), m.cmd == CTAPHID.cmdInit else { continue }
            guard m.payload.count >= 17, m.payload.prefix(8) == nonce else { r = CTAPHIDReassembler(cid: CTAPHID.broadcastCID); continue }
            cid = CTAPHID.cid(m.payload, at: 8)
            capabilities = m.payload[m.payload.startIndex + 16]
            guard cid != 0, cid != CTAPHID.broadcastCID else { throw CTAPHIDError.protocolViolation("bad channel id") }
            guard capabilities & CTAPHID.capCBOR != 0 else { throw CTAPHIDError.protocolViolation("device has no CBOR (CTAP2) support") }
            return
        }
    }

    /// Sends one CTAPHID_CBOR message (`payload` = command byte + CBOR) and returns the response (status byte + CBOR).
    /// Keepalives are reported through `keepalive`; `shouldCancel` is polled about every 100 ms and sends CTAPHID_CANCEL.
    func cbor(_ payload: Data, timeout: TimeInterval, keepalive: (UInt8) -> Void = { _ in }, shouldCancel: () -> Bool = { false }) throws -> Data {
        guard payload.count <= CTAPHID.maxPayload else { throw CTAPHIDError.protocolViolation("request too large") }
        for p in CTAPHID.split(cid: cid, cmd: CTAPHID.cmdCBOR, payload: payload) { try transport.write(p) }
        var r = CTAPHIDReassembler(cid: cid)
        let deadline = Date().addingTimeInterval(timeout)
        var cancelSent = false
        while true {
            if !cancelSent && shouldCancel() {
                for p in CTAPHID.split(cid: cid, cmd: CTAPHID.cmdCancel, payload: Data()) { try transport.write(p) }
                cancelSent = true
            }
            let left = deadline.timeIntervalSinceNow
            guard left > 0 else { throw CTAPHIDError.timeout }
            let packet: Data
            do { packet = try transport.read(timeout: min(left, 0.1)) } catch CTAPHIDError.timeout { continue }
            guard let m = try r.feed(packet) else { continue }
            switch m.cmd {
            case CTAPHID.cmdKeepalive: if let s = m.payload.first { keepalive(s) }
            case CTAPHID.cmdError: throw CTAPHIDError.device(m.payload.first ?? 0x7f)
            case CTAPHID.cmdCBOR: return m.payload
            default: throw CTAPHIDError.protocolViolation("unexpected command \(m.cmd)")
            }
        }
    }
}

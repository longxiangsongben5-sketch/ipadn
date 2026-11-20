import CommonCrypto
import CryptoKit
import Foundation
import Security
import ZIPFoundation

// Offline FairPlay decryption for downloaded IPAs, ported from the
// reference implementation used by the project's desktop decryptor.
// An IPA downloaded with an account carries, per binary, a SINF (inside
// SC_Info) whose priv record only that account's 16-byte FairPlay
// credential can open; the opened record yields a work key that derives
// every page key recorded in the matching SUPF. Decryption is a pure
// file transformation: nothing is launched or attached to, so it works
// in the app sandbox. The credential is account-bound — packages from a
// different account fail the SINF marker check and are rejected.
enum FairPlayDecryptor {
    struct Result {
        let url: URL
        let binaries: Int
        let pages: Int
    }

    private static let arm64: UInt32 = 0x0100_000C
    private static let pageSize = 4096

    // MARK: - Package driver (mirrors the reference IPA walk)

    static func decryptIPA(source: URL, credential: Data, onProgress: ((Double) -> Void)? = nil) throws -> Result {
        guard credential.count == 16 else {
            throw ToolError.message(AppText.text("復号キーが無効です（16バイト必須）"))
        }
        let archive = try Archive(url: source, accessMode: .read)
        let entries = archive.map { $0 }
        let names = entries.map(\.path)
        guard Set(names).count == names.count else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        let nameSet = Set(names)

        // Progress: count the encrypted pages up front (headers only, the
        // same walk the decrypt loop repeats) so the caller can show a real
        // percentage. A failed pre-count only loses the percentage — the
        // decrypt itself proceeds and reports phase-level updates instead.
        var plannedPages = 0
        if onProgress != nil {
            for supfPath in supfPaths(names: nameSet) {
                guard let split = supfPath.range(of: "/SC_Info/", options: .backwards) else { continue }
                let bundle = String(supfPath[..<split.lowerBound])
                let filename = String(supfPath[split.upperBound...])
                let isV5 = filename.hasSuffix(".v5.supf")
                let stem = isV5 ? String(filename.dropLast(8)) : String(filename.dropLast(5))
                let binaryPath = bundle + "/" + stem
                guard let binaryEntry = archive[binaryPath],
                      let binary = try? readEntry(binaryEntry, archive: archive),
                      let infos = try? encryptionInfos(in: binary) else { continue }
                plannedPages += infos.reduce(0) { $0 + $1.cryptsize / pageSize }
            }
        }
        var donePages = 0
        var lastReported = -1.0
        func report(_ fraction: Double) {
            guard let onProgress else { return }
            let clamped = min(1, max(0, fraction))
            guard clamped - lastReported >= 0.002 || clamped >= 1 else { return }
            lastReported = clamped
            onProgress(clamped)
        }
        report(0)

        var replacements: [String: Data] = [:]
        var totalPages = 0
        for supfPath in supfPaths(names: nameSet) {
            guard let split = supfPath.range(of: "/SC_Info/", options: .backwards) else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            let bundle = String(supfPath[..<split.lowerBound])
            let filename = String(supfPath[split.upperBound...])
            let isV5 = filename.hasSuffix(".v5.supf")
            let stem = isV5 ? String(filename.dropLast(8)) : String(filename.dropLast(5))
            let binaryPath = bundle + "/" + stem
            var sinfPath = bundle + "/SC_Info/" + stem + (isV5 ? ".v4.sinf" : ".sinf")
            if !nameSet.contains(sinfPath), isV5 {
                sinfPath = bundle + "/SC_Info/" + stem + ".sinf"
            }
            guard nameSet.contains(binaryPath) else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            guard let binaryEntry = archive[binaryPath] else { continue }
            let binary = try readEntry(binaryEntry, archive: archive)
            if try encryptionInfos(in: binary).isEmpty { continue }
            if !nameSet.contains(sinfPath) {
                guard let fallback = enclosingAppSinf(names: nameSet, bundle: bundle) else {
                    throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
                }
                sinfPath = fallback
            }
            guard let sinfEntry = archive[sinfPath], let supfEntry = archive[supfPath] else { continue }
            let sinf = try readEntry(sinfEntry, archive: archive)
            let supf = try readEntry(supfEntry, archive: archive)
            let (decrypted, pages) = try decryptBinary(source: binary, sinf: sinf, supf: supf, credential: credential, onPages: { delta in
                donePages += delta
                if plannedPages > 0 {
                    report(0.85 * min(1, Double(donePages) / Double(plannedPages)))
                }
            })
            replacements[binaryPath] = decrypted
            totalPages += pages
        }
        guard !replacements.isEmpty else {
            throw ToolError.message(AppText.text("このパッケージには復号できる暗号化バイナリがありません（復号済み、またはキーのアカウントと認証が不一致の可能性）"))
        }

        let working = LocalResources.support.appendingPathComponent("\(UUID().uuidString).decrypting.ipa")
        try? FileManager.default.removeItem(at: working)
        try FileManager.default.copyItem(at: source, to: working)
        defer { try? FileManager.default.removeItem(at: working) }
        do {
            let outArchive = try Archive(url: working, accessMode: .update)
            let total = replacements.count
            for (index, pair) in replacements.enumerated() {
                try replaceEntry(pair.key, data: pair.value, archive: outArchive)
                report(0.85 + 0.15 * Double(index + 1) / Double(max(1, total)))
            }
        }

        let stem = source.deletingPathExtension().lastPathComponent
        var destination = LocalResources.packages.appendingPathComponent("\(stem)_decrypted.ipa")
        var counter = 2
        while FileManager.default.fileExists(atPath: destination.path) {
            destination = LocalResources.packages.appendingPathComponent("\(stem)_decrypted-\(counter).ipa")
            counter += 1
        }
        try FileManager.default.moveItem(at: working, to: destination)
        report(1)
        return Result(url: destination, binaries: replacements.count, pages: totalPages)
    }

    private static func supfPaths(names: Set<String>) -> [String] {
        var byBinary: [String: String] = [:]
        for name in names.sorted() {
            if name.hasSuffix(".v5.supf") {
                byBinary[String(name.dropLast(8))] = name
            } else if name.hasSuffix(".supf") {
                let key = String(name.dropLast(5))
                if byBinary[key] == nil { byBinary[key] = name }
            }
        }
        return byBinary.values.sorted()
    }

    private static func enclosingAppSinf(names: Set<String>, bundle: String) -> String? {
        var parts = bundle.split(separator: "/").map(String.init)
        while !parts.isEmpty {
            let prefix = parts.joined(separator: "/")
            if prefix.hasSuffix(".app") {
                let scInfo = prefix + "/SC_Info/"
                let depth = scInfo.filter { $0 == "/" }.count
                let sinfs = names.filter {
                    $0.hasPrefix(scInfo) && $0.hasSuffix(".sinf") && $0.filter { $0 == "/" }.count == depth
                }.sorted()
                if !sinfs.isEmpty {
                    for suffix in [".sinf", ".v4.sinf"] {
                        let preferred = scInfo + (parts.last.map { String($0.dropLast(4)) } ?? "") + suffix
                        if sinfs.contains(preferred) { return preferred }
                    }
                    let unversioned = sinfs.filter { !$0.hasSuffix(".v4.sinf") }
                    return (unversioned.isEmpty ? sinfs : unversioned)[0]
                }
            }
            parts.removeLast()
        }
        return nil
    }

    private static func readEntry(_ entry: Entry, archive: Archive) throws -> Data {
        var data = Data()
        data.reserveCapacity(Int(entry.uncompressedSize))
        let checksum = try archive.extract(entry, consumer: { data.append($0) })
        guard checksum == entry.checksum else {
            throw ToolError.message(AppText.text("安装包已损坏，请重新下载"))
        }
        return data
    }

    private static func replaceEntry(_ path: String, data: Data, archive: Archive) throws {
        if let entry = archive[path] { try archive.remove(entry) }
        let scratch = LocalResources.support.appendingPathComponent("fp-entry-\(UUID().uuidString)", isDirectory: true)
        let file = scratch.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }
        try data.write(to: file, options: .atomic)
        try archive.addEntry(with: path, relativeTo: scratch, compressionMethod: .deflate)
    }

    // MARK: - Binary decryption (mirrors the reference core)

    struct EncryptionInfo {
        let base: Int
        let cryptoff: Int
        let cryptsize: Int
        let cryptidOffset: Int
        let subtype: UInt32
    }

    static func encryptionInfos(in data: Data) throws -> [EncryptionInfo] {
        let magic = try readBytes(data, 0, 4)
        var slices: [(base: Int, size: Int, subtype: UInt32)] = []
        if magic == [0xCA, 0xFE, 0xBA, 0xBE] {
            let count = Int(try be32(data, 4))
            guard count > 0, count <= 16, 8 + count * 20 <= data.count else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            for i in 0..<count {
                let off = 8 + i * 20
                let cpu = try be32(data, off)
                if cpu == arm64 {
                    slices.append((base: Int(try be32(data, off + 8)),
                                   size: Int(try be32(data, off + 12)),
                                   subtype: try be32(data, off + 4)))
                }
            }
        } else if magic == [0xCA, 0xFE, 0xBA, 0xBF] {
            let count = Int(try be32(data, 4))
            guard count > 0, count <= 16, 8 + count * 32 <= data.count else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            for i in 0..<count {
                let off = 8 + i * 32
                let cpu = try be32(data, off)
                if cpu == arm64 {
                    slices.append((base: Int(try be64(data, off + 8)),
                                   size: Int(try be64(data, off + 16)),
                                   subtype: try be32(data, off + 4)))
                }
            }
        } else if magic == [0xCF, 0xFA, 0xED, 0xFE] {
            slices.append((base: 0, size: data.count, subtype: try le32(data, 8)))
        } else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        guard !slices.isEmpty else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        var infos: [EncryptionInfo] = []
        for slice in slices {
            if let info = try sliceInfo(in: data, base: slice.base, sliceSize: slice.size, subtype: slice.subtype) {
                infos.append(info)
            }
        }
        return infos
    }

    private static func sliceInfo(in data: Data, base: Int, sliceSize: Int, subtype: UInt32) throws -> EncryptionInfo? {
        guard base + sliceSize <= data.count, base + 32 <= data.count else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        let magic = try le32(data, base)
        let cpu = try le32(data, base + 4)
        let ncmds = Int(try le32(data, base + 16))
        let sizeofcmds = Int(try le32(data, base + 20))
        guard magic == 0xFEED_FACF, cpu == arm64, ncmds <= 1000 else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        var pos = base + 32
        let commandsEnd = pos + sizeofcmds
        guard commandsEnd <= base + sliceSize else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        var found: [(cryptoff: Int, cryptsize: Int, cryptid: UInt32, cryptidOffset: Int)] = []
        for _ in 0..<ncmds {
            guard pos + 8 <= commandsEnd else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            let cmd = try le32(data, pos)
            let size = Int(try le32(data, pos + 4))
            guard size >= 8, pos + size <= commandsEnd else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            if cmd == 0x2C {
                guard size >= 24 else {
                    throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
                }
                found.append((cryptoff: Int(try le32(data, pos + 8)),
                              cryptsize: Int(try le32(data, pos + 12)),
                              cryptid: try le32(data, pos + 16),
                              cryptidOffset: pos + 16))
            }
            pos += size
        }
        guard pos == commandsEnd else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        if found.isEmpty { return nil }
        guard found.count == 1 else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        let entry = found[0]
        if entry.cryptid == 0 { return nil }
        guard entry.cryptid == 1, entry.cryptsize > 0, entry.cryptsize % pageSize == 0,
              entry.cryptoff + entry.cryptsize <= sliceSize,
              entry.cryptidOffset < base + entry.cryptoff else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        return EncryptionInfo(base: base, cryptoff: entry.cryptoff, cryptsize: entry.cryptsize,
                              cryptidOffset: entry.cryptidOffset, subtype: subtype)
    }

    static func decryptBinary(source: Data, sinf: Data, supf: Data, credential: Data, onPages: ((Int) -> Void)? = nil) throws -> (Data, Int) {
        let infos = try encryptionInfos(in: source)
        let work = try deriveWork16(credential: credential, sinf: sinf)
        var result = source
        var totalPages = 0
        for info in infos {
            let pageCount = info.cryptsize / pageSize
            let recordStart = try supfRecordOffset(supf: supf, requiredPages: pageCount, wantedSubtype: info.subtype)
            totalPages += pageCount
            var sinceReport = 0
            for localPage in 0..<pageCount {
                let recordOffset = recordStart + 32 * localPage
                guard recordOffset + 32 <= supf.count else {
                    throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
                }
                let record = subdata(supf, recordOffset, 32)
                let absoluteIndex = UInt64(info.base + info.cryptoff) / UInt64(pageSize) + UInt64(localPage)
                let key = try derivePageKey(wrapped: subdata(record, 0, 16), absoluteIndex: absoluteIndex, work: work)
                let start = info.base + info.cryptoff + pageSize * localPage
                let ciphertext = subdata(source, start, pageSize)
                let plain = try aes(key: key, iv: subdata(record, 16, 16), data: ciphertext, operation: CCOperation(kCCDecrypt))
                result.replaceSubrange(result.startIndex + start ..< result.startIndex + start + pageSize, with: plain)
                sinceReport += 1
                if sinceReport >= 64 {
                    onPages?(sinceReport)
                    sinceReport = 0
                }
            }
            if sinceReport > 0 { onPages?(sinceReport) }
            result.replaceSubrange(result.startIndex + info.cryptidOffset ..< result.startIndex + info.cryptidOffset + 4,
                                   with: [0, 0, 0, 0])
        }
        return (result, totalPages)
    }

    // MARK: - SINF / work key

    private static func sinfChildren(_ data: Data, _ start: Int, _ end: Int) throws -> [(type: [UInt8], contentStart: Int, contentEnd: Int)] {
        var children: [(type: [UInt8], contentStart: Int, contentEnd: Int)] = []
        var offset = start
        while offset < end {
            guard offset + 8 <= end else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            let size = Int(try be32(data, offset))
            guard size >= 8, offset + size <= end else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            children.append((type: try readBytes(data, offset + 4, 4), contentStart: offset + 8, contentEnd: offset + size))
            offset += size
        }
        return children
    }

    private static func sinfField(_ sinf: Data, _ wanted: [UInt8]) throws -> Data {
        let roots = try sinfChildren(sinf, 0, sinf.count)
        guard roots.count == 1, roots[0].type == [0x73, 0x69, 0x6E, 0x66] else { // "sinf"
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        let schi = try sinfChildren(sinf, roots[0].contentStart, roots[0].contentEnd)
            .filter { $0.type == [0x73, 0x63, 0x68, 0x69] } // "schi"
        guard schi.count == 1 else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        let fields = try sinfChildren(sinf, schi[0].contentStart, schi[0].contentEnd)
            .filter { $0.type == wanted }
        guard fields.count == 1 else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        return subdata(sinf, fields[0].contentStart, fields[0].contentEnd - fields[0].contentStart)
    }

    static func deriveWork16(credential: Data, sinf: Data) throws -> Data {
        var name = try sinfField(sinf, [0x6E, 0x61, 0x6D, 0x65]) // "name"
        if let cut = name.firstIndex(of: 0) { name = name.prefix(upTo: cut) }
        let iviv = try sinfField(sinf, [0x69, 0x76, 0x69, 0x76]) // "iviv"
        var priv = try sinfField(sinf, [0x70, 0x72, 0x69, 0x76]) // "priv"
        if priv.count == 440 {
            guard priv.suffix(8).allSatisfy({ $0 == 0 }) else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            priv = priv.dropLast(8)
        } else if priv.count != 448 {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        guard credential.count == 16, iviv.count == 16 else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        var digestInput = Data(name)
        digestInput.append(iviv)
        let iv = Data(Insecure.MD5.hash(data: digestInput))
        let key = Data(zip(credential, [UInt8](repeating: 0x30, count: 16)).map { $0 ^ $1 })
        let clear = try aes(key: key, iv: iv, data: priv, operation: CCOperation(kCCDecrypt))
        guard clear.count >= 48,
              [UInt8](clear.prefix(4)) == [0x69, 0x74, 0x75, 0x6E], // "itun"
              [UInt8](subdata(clear, 20, 4)) == [0x6B, 0x65, 0x79, 0x20], // "key "
              [UInt8](subdata(clear, 44, 4)) == [0x69, 0x76, 0x69, 0x76] else { // "iviv"
            throw ToolError.message(AppText.text("キーがこのパッケージの認証アカウントと一致しないため復号できません"))
        }
        return subdata(clear, 24, 16)
    }

    // MARK: - SUPF / page keys

    static func supfRecordOffset(supf: Data, requiredPages: Int, wantedSubtype: UInt32) throws -> Int {
        let supfVersion = supf.count > 0 ? supf[supf.startIndex] : 0
        guard supf.count >= 12,
              supfVersion == 3 || supfVersion == 5,
              ["507", "510", "612"].contains(String(bytes: subdata(supf, 1, 3), encoding: .ascii) ?? "") else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        let headerSize = supfVersion == 3 ? 32 : 12
        let count = Int(try be32(supf, 8))
        guard count > 0, count <= 16 else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        var pos = 12
        for _ in 0..<count {
            guard pos + 4 + headerSize <= supf.count else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            let length = Int(try be32(supf, pos))
            let cpu = try be32(supf, pos + 4)
            let subtype = try be32(supf, pos + 8)
            guard length >= headerSize, pos + 4 + length <= supf.count else {
                throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
            }
            let pages = Int(try be32(supf, pos + headerSize))
            if cpu == arm64, subtype == wantedSubtype {
                guard pages >= requiredPages, length >= headerSize + pages * 32 else {
                    throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
                }
                return pos + 4 + headerSize
            }
            pos += length + 4
        }
        throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
    }

    private static func sourceBlocks(wrapped: Data, absoluteIndex: UInt64) -> (Data, Data, Data) {
        var pageOffset = Data(count: 8)
        let value = absoluteIndex << 12
        for i in 0..<8 {
            pageOffset[i] = UInt8((value >> UInt64(56 - 8 * i)) & 0xFF)
        }
        var first = subdata(wrapped, 8, 8)
        first.append(pageOffset)
        var third = pageOffset
        third.append(subdata(wrapped, 0, 8))
        return (first, wrapped, third)
    }

    static func finish(_ state: [UInt16]) -> [UInt16] {
        let roundSelectors: [[(Int, Int)]] = [
            [(0, 1), (2, 3), (4, 5), (6, 7)],
            [(2, 1), (0, 3), (4, 7), (6, 5)],
            [(2, 0), (4, 1), (6, 3), (7, 5)],
            [(1, 2), (4, 0), (7, 3), (5, 6)],
        ]
        let roundConstants: [UInt32] = [0x6854_7C2E, 0x7E05_E1DE, 0xD495_038B, 0x0AB2_4ADD]
        let finalSelectors: [[Int]] = [[0, 1, 2, 3], [0, 2, 4, 6], [0, 3, 5, 7], [4, 5, 6, 7]]
        let finalConstants: [UInt32] = [0x5B71_98C7, 0xEB5D_E22C, 0x0F8A_A8FA, 0xF6E1_BB3F]
        var src = state
        for selectors in roundSelectors {
            var dst: [UInt16] = []
            for (pair, constant) in zip(selectors, roundConstants) {
                let mixed = UInt32(src[pair.0]) + UInt32(src[pair.1])
                let square = UInt64(mixed) * UInt64(mixed)
                let x = UInt32(truncatingIfNeeded: square) ^ (mixed >> 16) ^ constant
                dst.append(UInt16(truncatingIfNeeded: x))
                dst.append(UInt16(truncatingIfNeeded: x >> 16))
            }
            src = dst
        }
        var dst: [UInt16] = []
        for (quartet, constant) in zip(finalSelectors, finalConstants) {
            let a = (UInt32(src[quartet[1]]) << 16) | UInt32(src[quartet[0]])
            let b = (UInt32(src[quartet[3]]) << 16) | UInt32(src[quartet[2]])
            let mixed = a &+ b
            let square = UInt64(mixed) * UInt64(mixed)
            let x = UInt32(truncatingIfNeeded: square) ^ UInt32(truncatingIfNeeded: square >> 32) ^ constant
            dst.append(UInt16(truncatingIfNeeded: x))
            dst.append(UInt16(truncatingIfNeeded: x >> 16))
        }
        return zip(state, dst).map { $0 ^ $1 }
    }

    static func derivePageKey(wrapped: Data, absoluteIndex: UInt64, work: Data) throws -> Data {
        let (first, second, third) = sourceBlocks(wrapped: wrapped, absoluteIndex: absoluteIndex)
        func blocks(_ source: Data) throws -> [UInt16] {
            let encrypted = try aes(key: work, iv: nil, data: source, operation: CCOperation(kCCEncrypt))
            return unpackBE16(encrypted)
        }
        let a = try blocks(first)
        let b = try blocks(second)
        let c = try blocks(third)
        let combined = finish(zip(finish(zip(finish(a), b).map { $0 ^ $1 }), c).map { $0 ^ $1 })
        return packBE16(combined)
    }

    // MARK: - Crypto / byte helpers

    private static func aes(key: Data, iv: Data?, data: Data, operation: CCOperation) throws -> Data {
        var out = Data(count: data.count + kCCBlockSizeAES128)
        let outCapacity = out.count
        var outLength = 0
        let status = out.withUnsafeMutableBytes { outRaw in
            data.withUnsafeBytes { inRaw in
                key.withUnsafeBytes { keyRaw in
                    if let iv {
                        return iv.withUnsafeBytes { ivRaw in
                            CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), 0,
                                    keyRaw.baseAddress, key.count, ivRaw.baseAddress,
                                    inRaw.baseAddress, data.count,
                                    outRaw.baseAddress, outCapacity, &outLength)
                        }
                    }
                    return CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                                   keyRaw.baseAddress, key.count, nil,
                                   inRaw.baseAddress, data.count,
                                   outRaw.baseAddress, outCapacity, &outLength)
                }
            }
        }
        guard status == kCCSuccess else {
            throw ToolError.message(AppText.text("復号演算に失敗しました（\(Int(status))）"))
        }
        out.count = outLength
        return out
    }

    static func subdata(_ data: Data, _ offset: Int, _ length: Int) -> Data {
        data.subdata(in: data.startIndex + offset ..< data.startIndex + offset + length)
    }

    private static func readBytes(_ data: Data, _ offset: Int, _ length: Int) throws -> [UInt8] {
        guard offset >= 0, offset + length <= data.count else {
            throw ToolError.message(AppText.text("パッケージが破損しているか、形式がサポートされていません"))
        }
        return [UInt8](subdata(data, offset, length))
    }

    private static func be32(_ data: Data, _ offset: Int) throws -> UInt32 {
        let b = try readBytes(data, offset, 4)
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }

    private static func be64(_ data: Data, _ offset: Int) throws -> UInt64 {
        let b = try readBytes(data, offset, 8)
        return b.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    private static func le32(_ data: Data, _ offset: Int) throws -> UInt32 {
        let b = try readBytes(data, offset, 4)
        return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
    }

    private static func unpackBE16(_ data: Data) -> [UInt16] {
        (0..<(data.count / 2)).map { i in
            let base = data.startIndex + 2 * i
            return UInt16(data[base]) << 8 | UInt16(data[base + 1])
        }
    }

    private static func packBE16(_ values: [UInt16]) -> Data {
        var data = Data(count: values.count * 2)
        for (i, value) in values.enumerated() {
            data[2 * i] = UInt8(value >> 8)
            data[2 * i + 1] = UInt8(truncatingIfNeeded: value)
        }
        return data
    }
}

// The account's 16-byte FairPlay credential, imported once from a file
// the user obtained from their own jailbroken device. Stored in the
// keychain (this device only); never written to the download records.
enum FairPlayCredentialStore {
    private static var service: String {
        (Bundle.main.bundleIdentifier ?? "iPadn") + (LocalResources.isPreview ? ".preview.fairplay" : ".fairplay")
    }
    private static func query() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "fairplay-credential-v1"]
    }
    static var hasCredential: Bool { load() != nil }
    static func load() -> Data? {
        var request = query()
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, data.count == 16 else { return nil }
        return data
    }
    static func save(_ data: Data) throws {
        guard data.count == 16 else {
            throw ToolError.message(AppText.text("選択したファイルは16バイトの credential.bin ではありません"))
        }
        delete()
        var item = query()
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ToolError.message(AppText.text("復号キーを保存できませんでした（\(Int(status))）"))
        }
        LocalResources.defaults.set(Date().timeIntervalSince1970, forKey: "fairplayCredentialImportedAt")
    }
    enum CredentialFileImport { case imported, invalid, notCredential }

    /// Share-sheet route: a file named credential.bin (or any 16-byte
    /// .bin file) handed to the app is taken as the decrypt key, so the
    /// key can be imported even when the system file picker will not
    /// let the user select the file.
    static func importIfCredentialFile(_ url: URL) -> CredentialFileImport {
        guard url.isFileURL else { return .notCredential }
        let isBin = url.pathExtension.lowercased() == "bin"
        guard url.lastPathComponent.lowercased() == "credential.bin" || isBin else { return .notCredential }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url), data.count == 16 else { return .invalid }
        do { try save(data); return .imported } catch { return .invalid }
    }

    /// Paste route: decode a key pasted as text — 32 hex characters or
    /// Base64 — so the key can be imported with no file UI at all, for
    /// devices where neither the system picker nor the share sheet will
    /// hand the file over. Returns nil unless the text decodes to
    /// exactly 16 bytes.
    static func keyData(fromText text: String) -> Data? {
        let cleaned = text.filter { !$0.isWhitespace }
        if cleaned.count == 32 {
            var data = Data(capacity: 16)
            var index = cleaned.startIndex
            var valid = true
            while index < cleaned.endIndex {
                let next = cleaned.index(index, offsetBy: 2)
                guard let byte = UInt8(cleaned[index..<next], radix: 16) else { valid = false; break }
                data.append(byte)
                index = next
            }
            if valid, data.count == 16 { return data }
        }
        if let decoded = Data(base64Encoded: cleaned), decoded.count == 16 { return decoded }
        return nil
    }

    static func delete() {
        SecItemDelete(query() as CFDictionary)
        LocalResources.defaults.removeObject(forKey: "fairplayCredentialImportedAt")
    }
    static var importedAt: Date? {
        let value = LocalResources.defaults.double(forKey: "fairplayCredentialImportedAt")
        return value > 0 ? Date(timeIntervalSince1970: value) : nil
    }
}

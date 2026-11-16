import SwiftUI
import UIKit

/// Opens the install sheet for downloads that just finished (Settings ›
/// Downloads › Install When Downloaded), one at a time, above whatever page
/// or sheet is showing, once iPadn is in front and unlocked.
@MainActor
enum AutoInstall {
    private static weak var showing: UIViewController?

    /// From a publisher, which fires before the published value is set.
    static func presentSoon(_ store: ToolStore) {
        DispatchQueue.main.async { presentNext(store) }
    }

    static func presentNext(_ store: ToolStore) {
        guard !LocalResources.isPreview, showing == nil,
              UIApplication.shared.applicationState == .active, !AppLock.shared.locked,
              let id = store.downloads.pendingAutoInstalls.first else { return }
        guard let job = store.downloads.jobs.first(where: { $0.id == id && $0.status == .completed }) else {
            store.downloads.pendingAutoInstalls.removeAll { $0 == id }
            presentNext(store)
            return
        }
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
                .first(where: { $0.activationState == .foregroundActive }),
              let window = scene.windows.first(where: { $0.isKeyWindow && $0.windowLevel == .normal })
                ?? scene.windows.first(where: { $0.windowLevel == .normal && !$0.isHidden && $0.rootViewController != nil }),
              var top = window.rootViewController else { return }
        while let next = top.presentedViewController, !next.isBeingDismissed { top = next }
        guard !top.isBeingDismissed else { return }
        let sheet = AutoInstallHost(rootView: AnyView(
            PackageInstallationView(job: job, startsAutomatically: true)
                .environmentObject(store)
                .environmentObject(store.apple)
                .environmentObject(store.downloads)
                .environmentObject(store.signer)
                .tint(UX.tint)
                .toggleStyle(TintedSwitchToggleStyle())
                .preferredColorScheme(store.settings.appearance == "system" ? nil : store.settings.appearance == "dark" ? .dark : .light)))
        sheet.closed = {
            showing = nil
            Task { @MainActor in
                try? await Task.sleep(for: .milliseconds(400))
                presentNext(store)
            }
        }
        store.downloads.pendingAutoInstalls.removeAll { $0 == id }
        showing = sheet
        top.present(sheet, animated: true)
    }
}

private final class AutoInstallHost: UIHostingController<AnyView> {
    var closed: (() -> Void)?
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Gone for good, not just covered by something it presented.
        if presentingViewController == nil || isBeingDismissed {
            closed?(); closed = nil
        }
    }
}

/// Shown above the download list while downloads wait for Wi-Fi.
struct WiFiWaitRow: View {
    @EnvironmentObject private var manager: DownloadManager
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "wifi.exclamationmark").foregroundStyle(.orange).font(.title3)
            VStack(alignment: .leading, spacing: 8) {
                Text("等待 Wi‑Fi").font(.subheadline.weight(.semibold))
                Text("当前只有蜂窝数据，下载会在连上 Wi‑Fi 后继续。").font(.subheadline).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button("仍使用蜂窝数据下载") { manager.downloadOverCellular() }.buttonStyle(CapsuleButtonStyle())
                    .accessibilityIdentifier("downloads.cellular")
            }
        }
        .padding(.vertical, 6)
    }
}

/// Runs the automatic decrypt for downloads started from a "復号" button
/// (detail header or version row), one at a time, above whatever page is
/// showing, once iPadn is in front and unlocked. Mirrors AutoInstall.
/// The decrypt itself is a detached file transformation; dismissing the
/// progress sheet lets it finish in the background, and the share sheet
/// for the result is presented when it lands.
@MainActor
enum AutoDecrypt {
    private static var busy = false
    private static weak var host: AutoDecryptHost?
    private static var hostDismissed = false
    private static var shareShowing = false
    /// Decrypted packages whose share sheet still has to be shown.
    private static var pendingShares: [URL] = []

    /// From a publisher, which fires before the published value is set.
    static func presentSoon(_ store: ToolStore) {
        DispatchQueue.main.async { presentNext(store) }
    }

    static func presentNext(_ store: ToolStore) {
        guard !LocalResources.isPreview,
              UIApplication.shared.applicationState == .active, !AppLock.shared.locked else { return }
        // A finished decrypt's share sheet comes before the next decrypt.
        if host == nil, !shareShowing, let url = pendingShares.first, let top = topController() {
            pendingShares.removeFirst()
            shareShowing = true
            let activity = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            activity.popoverPresentationController?.sourceView = top.view
            activity.completionWithItemsHandler = { _, _, _, _ in
                Task { @MainActor in
                    shareShowing = false
                    presentNext(store)
                }
            }
            top.present(activity, animated: true)
            return
        }
        guard !busy, host == nil, !shareShowing, let id = store.downloads.pendingAutoDecrypts.first else { return }
        guard let job = store.downloads.jobs.first(where: { $0.id == id && $0.status == .completed }),
              let file = store.downloads.fileURL(job) else {
            store.downloads.pendingAutoDecrypts.removeAll { $0 == id }
            store.downloads.markWaitingDecrypt(id, false)
            presentNext(store)
            return
        }
        guard let credential = FairPlayCredentialStore.load() else {
            store.downloads.pendingAutoDecrypts.removeAll { $0 == id }
            store.downloads.markWaitingDecrypt(id, false)
            store.errorMessage = AppText.text("FairPlay復号キーがまだインポートされていません。先に「アカウント › メンテナンス › FairPlay復号キー」でキーをテキストで取り込んでください")
            presentNext(store)
            return
        }
        guard let top = topController() else { return }
        store.downloads.pendingAutoDecrypts.removeAll { $0 == id }
        busy = true
        hostDismissed = false
        let name = [job.app.name, job.app.version].filter { !$0.isEmpty }.joined(separator: " ")
        let state = AutoDecryptState(name: name)
        let sheet = AutoDecryptHost(rootView: AnyView(
            AutoDecryptProgressView(state: state)
                .tint(UX.tint)
                .preferredColorScheme(store.settings.appearance == "system" ? nil : store.settings.appearance == "dark" ? .dark : .light)))
        sheet.isModalInPresentation = true
        state.onBackground = { sheet.dismiss(animated: true) }
        sheet.closed = { if host === sheet { host = nil; hostDismissed = true } }
        host = sheet
        top.present(sheet, animated: true)
        Task { @MainActor in
            defer { busy = false }
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    try FairPlayDecryptor.decryptIPA(source: file, credential: credential)
                }.value
                store.downloads.markWaitingDecrypt(id, false)
                store.infoMessage = AppText.text("復号完了：\(result.binaries) 個のバイナリ、合計 \(result.pages) ページ")
                if let sheet = host, !hostDismissed {
                    shareShowing = true
                    let activity = UIActivityViewController(activityItems: [result.url], applicationActivities: nil)
                    activity.popoverPresentationController?.sourceView = sheet.view
                    activity.completionWithItemsHandler = { _, _, _, _ in
                        sheet.dismiss(animated: true)
                        Task { @MainActor in
                            shareShowing = false
                            try? await Task.sleep(for: .milliseconds(400))
                            presentNext(store)
                        }
                    }
                    sheet.present(activity, animated: true)
                } else {
                    pendingShares.append(result.url)
                    presentNext(store)
                }
            } catch {
                store.downloads.markWaitingDecrypt(id, false)
                store.errorMessage = error.localizedDescription
                if let sheet = host, !hostDismissed { sheet.dismiss(animated: true) }
                presentNext(store)
            }
        }
    }

    private static func topController() -> UIViewController? {
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
                .first(where: { $0.activationState == .foregroundActive }),
              let window = scene.windows.first(where: { $0.isKeyWindow && $0.windowLevel == .normal })
                ?? scene.windows.first(where: { $0.windowLevel == .normal && !$0.isHidden && $0.rootViewController != nil }),
              var top = window.rootViewController else { return nil }
        while let next = top.presentedViewController, !next.isBeingDismissed { top = next }
        return top.isBeingDismissed ? nil : top
    }
}

private final class AutoDecryptHost: UIHostingController<AnyView> {
    var closed: (() -> Void)?
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Gone for good, not just covered by the share sheet it presented.
        if presentingViewController == nil || isBeingDismissed {
            closed?(); closed = nil
        }
    }
}

@MainActor
final class AutoDecryptState: ObservableObject {
    let name: String
    var onBackground: (() -> Void)?
    init(name: String) { self.name = name }
}

struct AutoDecryptProgressView: View {
    @ObservedObject var state: AutoDecryptState
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.open")
                .font(.largeTitle)
                .foregroundStyle(Color.accentColor)
            ProgressView()
            Text("復号中…")
                .font(.headline)
            Text(state.name)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .multilineTextAlignment(.center)
            Text("大きなアプリでは数分かかることがあります")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button("バックグラウンドで続行") { state.onBackground?() }
                .buttonStyle(CapsuleButtonStyle())
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

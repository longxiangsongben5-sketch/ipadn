import SwiftUI
import UniformTypeIdentifiers

/// Import and manage the 16-byte FairPlay credential used by the
/// "decrypt & export" action on downloaded packages. The credential is
/// account-bound key material extracted once from the user's own
/// jailbroken device; it stays in the keychain and is never uploaded.
struct FairPlayKeyView: View {
    @EnvironmentObject private var store: ToolStore
    @State private var importing = false
    @State private var confirmingDelete = false
    @State private var hasCredential = FairPlayCredentialStore.hasCredential
    @State private var importedAt = FairPlayCredentialStore.importedAt

    var body: some View {
        Form {
            Section {
                LabeledContent(AppText.text("状態")) {
                    Text(hasCredential ? AppText.text("インポート済み") : AppText.text("未インポート"))
                        .foregroundStyle(hasCredential ? .green : .secondary)
                }
                if let importedAt {
                    LabeledContent(AppText.text("インポート日時")) {
                        Text(importedAt, format: .dateTime.year().month().day().hour().minute())
                    }
                }
            } footer: {
                Text("復号キー（credential.bin、16バイト）はダウンロードに使った Apple アカウントに紐づいています。自分の脱獄デバイスから一度だけ取り出してインポートすれば、ダウンロード一覧のパッケージで「復号して書き出す」を選ぶだけで、この端末上で復号済みパッケージを生成できます。キーはこの端末のキーチェーンにのみ保存され、アップロードされません。")
            }
            Section {
                Button(hasCredential ? AppText.text("キーファイルを置き換える") : AppText.text("credential.bin をインポート"), systemImage: "square.and.arrow.down") {
                    importing = true
                }
                if hasCredential {
                    Button(AppText.text("キーを削除"), systemImage: "trash", role: .destructive) {
                        confirmingDelete = true
                    }
                }
            } footer: {
                Text("アカウントが違うキーではパッケージの認証を開けないため、壊れたファイルは生成されず、復号時にエラーになります。")
            }
        }
        .navigationTitle(AppText.text("FairPlay復号キー"))
        .fileImporter(isPresented: $importing, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let url):
                do {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    let data = try Data(contentsOf: url)
                    try FairPlayCredentialStore.save(data)
                    hasCredential = true
                    importedAt = FairPlayCredentialStore.importedAt
                    store.infoMessage = AppText.text("復号キーをインポートしました")
                } catch {
                    store.errorMessage = error.localizedDescription
                }
            case .failure(let error):
                store.errorMessage = error.localizedDescription
            }
        }
        .alert("復号キーを削除しますか？", isPresented: $confirmingDelete) {
            Button(AppText.text("キャンセル"), role: .cancel) { }
            Button(AppText.text("削除"), role: .destructive) {
                FairPlayCredentialStore.delete()
                hasCredential = false
                importedAt = nil
                store.infoMessage = AppText.text("復号キーを削除しました")
            }
        } message: {
            Text("パッケージを復号するには credential.bin の再インポートが必要になります。")
        }
    }
}

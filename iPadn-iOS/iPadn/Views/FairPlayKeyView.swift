import SwiftUI

/// Import and manage the 16-byte FairPlay credential used by the
/// "decrypt & export" action on downloaded packages. The credential is
/// account-bound key material extracted once from the user's own
/// jailbroken device; it stays in the keychain and is never uploaded.
///
/// Import is text-only on this screen: the system file picker does not
/// open reliably on current iOS builds, so the key is pasted as hex or
/// Base64 instead. Sharing credential.bin to iPadn from the Files app
/// still imports it automatically (handled at the app level).
struct FairPlayKeyView: View {
    @EnvironmentObject private var store: ToolStore
    @State private var confirmingDelete = false
    @State private var hasCredential = FairPlayCredentialStore.hasCredential
    @State private var importedAt = FairPlayCredentialStore.importedAt
    @State private var pastedKey = ""
    @State private var pasteNote: String?
    @State private var pasteNoteIsError = false

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
                if hasCredential {
                    Button(AppText.text("キーを削除"), systemImage: "trash", role: .destructive) {
                        confirmingDelete = true
                    }
                }
            } footer: {
                Text("復号キー（credential.bin、16バイト）はダウンロードに使った Apple アカウントに紐づいています。自分の脱獄デバイスから一度だけ取り出してインポートすれば、ダウンロード一覧のパッケージで「復号して書き出す」を選ぶだけで、この端末上で復号済みパッケージを生成できます。キーはこの端末のキーチェーンにのみ保存され、アップロードされません。アカウントが違うキーではパッケージの認証を開けないため、壊れたファイルは生成されず、復号時にエラーになります。")
            }
            Section {
                TextField(AppText.text("16進数（32文字）または Base64 のキー"), text: $pastedKey, axis: .vertical)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(3...6)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button(AppText.text("貼り付けて取り込む")) {
                    importPastedKey()
                }
                .disabled(pastedKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                if let pasteNote {
                    Text(pasteNote)
                        .font(.footnote)
                        .foregroundStyle(pasteNoteIsError ? .red : .green)
                }
            } header: {
                Text(AppText.text("テキストで取り込む"))
            } footer: {
                Text("credential.bin の中身を16進数（32文字）または Base64 で貼り付けて取り込めます。ファイルアプリから credential.bin を iPadn に共有しても自動で取り込まれます。")
            }
        }
        .navigationTitle(AppText.text("FairPlay復号キー"))
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

    private func noteImported() {
        hasCredential = true
        importedAt = FairPlayCredentialStore.importedAt
    }

    private func importPastedKey() {
        guard let data = FairPlayCredentialStore.keyData(fromText: pastedKey) else {
            pasteNote = AppText.text("貼り付けた内容をキーとして読み取れませんでした（16進数32文字、または Base64 で16バイトになる文字列にしてください）")
            pasteNoteIsError = true
            return
        }
        do {
            try FairPlayCredentialStore.save(data)
            pastedKey = ""
            pasteNote = AppText.text("復号キーをインポートしました")
            pasteNoteIsError = false
            noteImported()
        } catch {
            pasteNote = error.localizedDescription
            pasteNoteIsError = true
        }
    }
}

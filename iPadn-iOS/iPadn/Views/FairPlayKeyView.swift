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
    @State private var pastedKey = ""
    @State private var pasteNote: String?
    @State private var pasteNoteIsError = false
    @State private var containerFiles: [ContainerFile] = []
    @State private var fileNote: String?
    @State private var fileNoteIsError = false

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
                Text("credential.bin の中身を16進数（32文字）または Base64 で貼り付けて取り込めます。")
            }
            Section {
                if containerFiles.isEmpty {
                    Text(AppText.text("ファイルが見つかりません"))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(containerFiles) { file in
                        Button {
                            importContainerFile(file)
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(file.name)
                                        .foregroundStyle(.primary)
                                        .lineLimit(1)
                                    Text(file.location)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(file.size.byteLabel)
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                if let fileNote {
                    Text(fileNote)
                        .font(.footnote)
                        .foregroundStyle(fileNoteIsError ? .red : .green)
                }
            } header: {
                Text(AppText.text("アプリ内のファイルから取り込む"))
            } footer: {
                Text("このアプリの保存領域にあるファイルです。credential.bin（16バイト）をタップすると取り込みを試みます。")
            }
        }
        .onAppear { refreshContainerFiles() }
        .navigationTitle(AppText.text("FairPlay復号キー"))
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
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

    private func importContainerFile(_ file: ContainerFile) {
        do {
            let data = try Data(contentsOf: file.url)
            try FairPlayCredentialStore.save(data)
            fileNote = AppText.text("復号キーをインポートしました")
            fileNoteIsError = false
            noteImported()
        } catch {
            fileNote = error.localizedDescription
            fileNoteIsError = true
        }
        refreshContainerFiles()
    }

    /// Files already inside the app container: the Documents folder, the
    /// share-sheet Inbox (a share may have delivered credential.bin there
    /// even when the open-URL hook never fired), and the Packages folder
    /// downloads live in. Listed directly, no system picker involved.
    private func refreshContainerFiles() {
        let fm = FileManager.default
        let documents = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let directories: [(String, URL)] = [
            ("Documents", documents),
            ("Inbox", documents.appendingPathComponent("Inbox", isDirectory: true)),
            ("Packages", LocalResources.packages)
        ]
        var found: [ContainerFile] = []
        for (label, directory) in directories {
            guard let entries = try? fm.contentsOfDirectory(
                at: directory,
                includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
                options: [.skipsHiddenFiles]) else { continue }
            for entry in entries {
                guard let values = try? entry.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
                      values.isRegularFile == true else { continue }
                found.append(ContainerFile(url: entry, location: label, size: Int64(values.fileSize ?? 0)))
            }
        }
        // 16-byte files (the credential's size) first, then by location and name.
        containerFiles = found.sorted {
            ($0.size == 16 ? 0 : 1, $0.location, $0.name) < ($1.size == 16 ? 0 : 1, $1.location, $1.name)
        }
    }
}

private struct ContainerFile: Identifiable {
    let url: URL
    let location: String
    let size: Int64
    var id: String { url.path }
    var name: String { url.lastPathComponent }
}

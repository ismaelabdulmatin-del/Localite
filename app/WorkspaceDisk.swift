import Foundation

enum WorkspaceMode {
    case none
    case privateCopy(URL)
    case sharedFolder(URL)
}

extension WorkspaceMode {
    var isPrivateCopy: Bool {
        if case .privateCopy = self { return true }
        return false
    }

    var bootArgument: String {
        switch self {
        case .none: return ""
        case .privateCopy: return " localite.workspace=private"
        case .sharedFolder: return " localite.workspace=shared"
        }
    }
}

enum WorkspaceCopyError: LocalizedError {
    case sourceContainsSymbolicLink(String)

    var errorDescription: String? {
        switch self {
        case .sourceContainsSymbolicLink(let path):
            return "The project contains a symbolic link that cannot be imported into the isolated workspace: \(path)"
        }
    }
}

enum WorkspaceCopy {
    private static var managedRoot: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Localite/Workspaces", isDirectory: true)
            .standardizedFileURL
    }

    static func importProject(from source: URL) throws -> URL {
        if try source.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true {
            throw WorkspaceCopyError.sourceContainsSymbolicLink(source.lastPathComponent)
        }
        try rejectSymbolicLinks(in: source)
        try FileManager.default.createDirectory(at: managedRoot, withIntermediateDirectories: true)
        let copy = managedRoot.appendingPathComponent("workspace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: false)
        do {
            for item in try FileManager.default.contentsOfDirectory(
                at: source,
                includingPropertiesForKeys: [.isSymbolicLinkKey]
            ) {
                try FileManager.default.copyItem(
                    at: item,
                    to: copy.appendingPathComponent(item.lastPathComponent)
                )
            }
            return copy
        } catch {
            try? FileManager.default.removeItem(at: copy)
            throw error
        }
    }

    private static func rejectSymbolicLinks(in source: URL) throws {
        var enumerationError: Error?
        guard let enumerator = FileManager.default.enumerator(
            at: source,
            includingPropertiesForKeys: [.isSymbolicLinkKey],
            options: [],
            errorHandler: { _, error in
                enumerationError = error
                return false
            }
        ) else {
            throw CocoaError(.fileReadUnknown)
        }

        for case let file as URL in enumerator {
            if try file.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true {
                throw WorkspaceCopyError.sourceContainsSymbolicLink(file.lastPathComponent)
            }
        }
        if let enumerationError { throw enumerationError }
    }
}

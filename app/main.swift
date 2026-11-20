// Localite.app — isolated AWS workbench backed by a lightweight Linux VM.

import Cocoa
import Virtualization

let servicePort: UInt16 = 4566
let vsockPort: UInt32 = 4566

// MARK: - TCP <-> vsock forwarder (plain BSD sockets)

final class PortForwarder {
    private var listenFd: Int32 = -1
    private(set) var connections = 0

    func start(port: UInt16, device: VZVirtioSocketDevice, onError: @escaping (String) -> Void) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { onError("socket() failed"); return }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")  // loopback only, never LAN-exposed
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0, listen(fd, 128) == 0 else {
            onError("cannot listen on 127.0.0.1:\(port) (is LocalStack or another Localite already using it?)")
            close(fd); return
        }
        listenFd = fd
        Thread.detachNewThread { [weak self] in
            while let self = self, self.listenFd >= 0 {
                let client = accept(self.listenFd, nil, nil)
                if client < 0 { if self.listenFd < 0 { return }; continue }
                self.connections += 1
                DispatchQueue.main.async {  // VZ calls must be on the main queue
                    device.connect(toPort: vsockPort) { result in
                        switch result {
                        case .success(let conn): PortForwarder.pump(client: client, conn: conn)
                        case .failure: close(client)  // guest not ready yet
                        }
                    }
                }
            }
        }
    }

    func stop() {
        let fd = listenFd; listenFd = -1
        if fd >= 0 { shutdown(fd, SHUT_RDWR); close(fd) }
    }

    private static func pump(client: Int32, conn: VZVirtioSocketConnection) {
        let vfd = conn.fileDescriptor
        let group = DispatchGroup()
        func copy(_ from: Int32, _ to: Int32) {
            group.enter()
            Thread.detachNewThread {
                var buf = [UInt8](repeating: 0, count: 16 * 1024)
                loop: while true {
                    let n = read(from, &buf, buf.count)
                    if n <= 0 { break }
                    var off = 0
                    while off < n {
                        let w = buf.withUnsafeBytes { write(to, $0.baseAddress! + off, n - off) }
                        if w <= 0 { break loop }
                        off += w
                    }
                }
                shutdown(to, SHUT_WR)
                group.leave()
            }
        }
        copy(client, vfd)
        copy(vfd, client)
        group.notify(queue: .global()) {
            close(client)
            DispatchQueue.main.async { conn.close() }
        }
    }
}

// MARK: - VM controller

final class VMController: NSObject, VZVirtualMachineDelegate {
    enum State { case stopped, starting, running, failed(String) }
    var state: State = .stopped { didSet { onState?(state) } }
    var onState: ((State) -> Void)?
    var onLog: ((String) -> Void)?
    var onWorkspaceStatus: ((String) -> Void)?

    private var vm: VZVirtualMachine?
    private let forwarder = PortForwarder()
    private let consoleOut = Pipe()
    private let consoleIn = Pipe()
    private var carry = ""
    private var lastWorkspaceMessage = ""

    func start(kernel: URL, initrd: URL, workspace: WorkspaceMode) {
        switch state { case .stopped, .failed: break; default: return }
        state = .starting
        carry = ""
        lastWorkspaceMessage = ""
        do {
            let cfg = VZVirtualMachineConfiguration()
            cfg.cpuCount = min(max(2, VZVirtualMachineConfiguration.minimumAllowedCPUCount),
                               VZVirtualMachineConfiguration.maximumAllowedCPUCount)
            cfg.memorySize = max(1024 * 1024 * 1024, VZVirtualMachineConfiguration.minimumAllowedMemorySize)

            let boot = VZLinuxBootLoader(kernelURL: kernel)
            boot.initialRamdiskURL = initrd
            boot.commandLine = "console=hvc0 rdinit=/init quiet loglevel=3\(workspace.bootArgument)"
            cfg.bootLoader = boot

            switch workspace {
            case .none:
                break
            case .privateCopy(let url), .sharedFolder(let url):
                let directory = VZSharedDirectory(url: url, readOnly: false)
                let share = VZSingleDirectoryShare(directory: directory)
                let tag = workspace.isPrivateCopy ? "localite-private" : "localite-shared"
                let device = VZVirtioFileSystemDeviceConfiguration(tag: tag)
                device.share = share
                cfg.directorySharingDevices = [device]
            }

            let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
            serial.attachment = VZFileHandleSerialPortAttachment(
                fileHandleForReading: consoleIn.fileHandleForReading,
                fileHandleForWriting: consoleOut.fileHandleForWriting)
            cfg.serialPorts = [serial]
            cfg.socketDevices = [VZVirtioSocketDeviceConfiguration()]
            cfg.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
            cfg.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
            try cfg.validate()

            let machine = VZVirtualMachine(configuration: cfg)
            machine.delegate = self
            vm = machine

            consoleOut.fileHandleForReading.readabilityHandler = { [weak self] h in
                let data = h.availableData
                guard !data.isEmpty, let s = String(data: data, encoding: .utf8) else { return }
                DispatchQueue.main.async { self?.ingest(s) }
            }
            machine.start { [weak self] result in
                guard let self = self else { return }
                switch result {
                case .success:
                    if let dev = machine.socketDevices.first as? VZVirtioSocketDevice {
                        self.forwarder.start(port: servicePort, device: dev) { msg in
                            self.state = .failed(msg)
                        }
                    }
                case .failure(let e): self.state = .failed("VM failed to start: \(e.localizedDescription)")
                }
            }
        } catch {
            state = .failed("Invalid VM configuration: \(error.localizedDescription)")
        }
    }

    func stop() {
        forwarder.stop()
        consoleOut.fileHandleForReading.readabilityHandler = nil
        if let machine = vm, machine.canStop {
            machine.stop { [weak self] _ in DispatchQueue.main.async { self?.state = .stopped } }
        } else { state = .stopped }
        vm = nil
    }

    private func ingest(_ s: String) {
        onLog?(s)
        carry += s
        for marker in [
            "workspace: isolated and mounted at /workspace",
            "private project copy mounted at /workspace",
            "private project copy mount failed",
            "explicitly shared host folder mounted at /workspace",
            "shared folder mount failed"
        ] {
            if let range = carry.range(of: marker, options: .backwards) {
                let message = String(carry[range.lowerBound...].prefix(160))
                if message != lastWorkspaceMessage {
                    lastWorkspaceMessage = message
                    onWorkspaceStatus?(message)
                }
                break
            }
        }
        if carry.contains("LOCALITE READY") { if case .starting = state { state = .running } }
        if carry.count > 4096 { carry = String(carry.suffix(1024)) }
    }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        forwarder.stop(); vm = nil; state = .stopped
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        forwarder.stop(); vm = nil; state = .failed("VM stopped: \(error.localizedDescription)")
    }
}

// MARK: - UI

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 940, height: 850),
                          styleMask: [.titled, .closable, .miniaturizable],
                          backing: .buffered, defer: false)
    let vmc = VMController()
    let status = NSTextField(labelWithString: "Stopped")
    let endpoint = NSTextField(labelWithString: "")
    let button = NSButton(title: "Start", target: nil, action: nil)
    let stopButton = NSButton(title: "Stop", target: nil, action: nil)
    let importButton = NSButton(title: "Import private project…", target: nil, action: nil)
    let shareButton = NSButton(title: "Share folder…", target: nil, action: nil)
    let privateButton = NSButton(title: "Use imported copy", target: nil, action: nil)
    let clearWorkspaceButton = NSButton(title: "No workspace", target: nil, action: nil)
    let workspaceStatus = NSTextField(labelWithString: "No project workspace selected")
    let servicePicker = NSPopUpButton(frame: .zero, pullsDown: false)
    let operationPicker = NSPopUpButton(frame: .zero, pullsDown: false)
    let parametersView = NSTextView()
    let responseView = NSTextView()
    let runButton = NSButton(title: "Run AWS request", target: nil, action: nil)
    let browseButton = NSButton(title: "Browse resources", target: nil, action: nil)
    let copyEnvButton = NSButton(title: "Copy AWS env", target: nil, action: nil)
    let guideButton = NSButton(title: "Getting started", target: nil, action: nil)
    let logView = NSTextView()
    private let resources = Bundle.main.resourceURL!
    private var guideWindow: NSWindow?
    private var workspaceMode: WorkspaceMode = .none
    private var workspaceWarning: String?
    private var isImportingWorkspace = false

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.regular)
        window.title = "Localite"
        window.delegate = self
        window.center()

        let logo = NSImageView()
        logo.image = NSImage(contentsOf: resources.appendingPathComponent("logo.png"))
        logo.imageScaling = .scaleProportionallyUpOrDown
        logo.translatesAutoresizingMaskIntoConstraints = false

        status.font = .systemFont(ofSize: 15, weight: .medium)
        endpoint.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        endpoint.isSelectable = true
        button.target = self; button.action = #selector(toggle)
        button.bezelStyle = .rounded
        stopButton.target = self; stopButton.action = #selector(stopVM)
        stopButton.bezelStyle = .rounded
        importButton.target = self; importButton.action = #selector(importProject)
        shareButton.target = self; shareButton.action = #selector(shareFolder)
        privateButton.target = self; privateButton.action = #selector(usePrivateWorkspace)
        clearWorkspaceButton.target = self; clearWorkspaceButton.action = #selector(clearWorkspace)
        for control in [importButton, shareButton, privateButton, clearWorkspaceButton] {
            control.bezelStyle = .rounded
        }
        workspaceStatus.lineBreakMode = .byTruncatingMiddle
        workspaceStatus.font = .systemFont(ofSize: 12)

        logView.isEditable = false
        logView.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.backgroundColor = NSColor(white: 0.97, alpha: 1)
        let scroll = NSScrollView()
        scroll.documentView = logView
        scroll.hasVerticalScroller = true
        scroll.borderType = .lineBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        servicePicker.addItems(withTitles: AWSWorkbench.services)
        servicePicker.target = self
        servicePicker.action = #selector(serviceChanged)
        operationPicker.target = self
        operationPicker.action = #selector(operationChanged)
        copyEnvButton.target = self
        copyEnvButton.action = #selector(copyEnv)
        copyEnvButton.bezelStyle = .rounded
        guideButton.target = self
        guideButton.action = #selector(openGuide)
        guideButton.bezelStyle = .rounded
        configureTextView(parametersView, placeholder: "JSON parameters")
        configureTextView(responseView, placeholder: "AWS response")
        responseView.isEditable = false
        runButton.target = self
        runButton.action = #selector(runRequest)
        browseButton.target = self
        browseButton.action = #selector(browseResources)
        runButton.bezelStyle = .rounded
        browseButton.bezelStyle = .rounded
        parametersView.string = AWSWorkbench.defaultPayload(for: "ListBuckets")

        let row = NSStackView(views: [button, stopButton, copyEnvButton, guideButton, status, endpoint])
        row.spacing = 12
        let workspaceButtons = NSStackView(views: [importButton, shareButton, privateButton, clearWorkspaceButton])
        workspaceButtons.spacing = 8
        workspaceButtons.distribution = .fillProportionally
        let workspaceStack = NSStackView(views: [workspaceStatus, workspaceButtons])
        workspaceStack.orientation = .vertical
        workspaceStack.alignment = .leading
        workspaceStack.spacing = 8

        let awsHeading = NSTextField(labelWithString: "AWS testing workbench")
        awsHeading.font = .systemFont(ofSize: 16, weight: .semibold)
        let editorNote = NSTextField(labelWithString: "Connect your SDK or AWS CLI at localhost:4566. The imported workspace is file storage; Localite does not execute project code.")
        editorNote.font = .systemFont(ofSize: 11)
        editorNote.textColor = .secondaryLabelColor
        editorNote.maximumNumberOfLines = 2
        editorNote.lineBreakMode = .byWordWrapping
        let requestControls = NSStackView(views: [servicePicker, operationPicker, browseButton, runButton])
        requestControls.spacing = 8
        requestControls.distribution = .fillProportionally
        let paramsScroll = textScrollView(parametersView, height: 112)
        let responseScroll = textScrollView(responseView, height: 150)
        let logHeading = NSTextField(labelWithString: "Emulator logs")
        logHeading.font = .systemFont(ofSize: 14, weight: .semibold)
        let stack = NSStackView(views: [logo, row, workspaceStack, awsHeading, editorNote, requestControls,
                                        paramsScroll, responseScroll, logHeading, scroll])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 14, left: 20, bottom: 20, right: 20)
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor),
            stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor),
            stack.bottomAnchor.constraint(equalTo: window.contentView!.bottomAnchor),
            logo.heightAnchor.constraint(equalToConstant: 112),
            logo.widthAnchor.constraint(equalToConstant: 330),
            stack.widthAnchor.constraint(equalTo: window.contentView!.widthAnchor),
            paramsScroll.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40),
            responseScroll.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40),
            scroll.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -40),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 120),
            servicePicker.widthAnchor.constraint(greaterThanOrEqualToConstant: 115),
            operationPicker.widthAnchor.constraint(greaterThanOrEqualToConstant: 160),
        ])

        vmc.onLog = { [weak self] s in
            guard let tv = self?.logView else { return }
            tv.textStorage?.append(NSAttributedString(string: s, attributes: [
                .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular),
                .foregroundColor: NSColor.black]))
            if let storage = tv.textStorage, storage.length > 200_000 {
                storage.deleteCharacters(in: NSRange(location: 0, length: storage.length - 150_000))
            }
            tv.scrollToEndOfDocument(nil)
        }
        vmc.onState = { [weak self] st in DispatchQueue.main.async {
            self?.render(st)
            self?.updateWorkspaceControls()
            if case .stopped = st { self?.updateWorkspaceLabel() }
        } }
        vmc.onWorkspaceStatus = { [weak self] message in DispatchQueue.main.async {
            self?.workspaceStatus.stringValue = message
        } }
        loadWorkspace()
        serviceChanged()
        updateWorkspaceControls()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        begin()
    }

    func render(_ st: VMController.State) {
        switch st {
        case .stopped:
            status.stringValue = "Stopped"; button.title = "Start"; endpoint.stringValue = ""
            stopButton.isEnabled = false
        case .starting:
            status.stringValue = "Starting Linux sandbox…"; button.title = "Starting…"
            stopButton.isEnabled = true
        case .running:
            status.stringValue = "● Running · Moto AWS API"; button.title = "Running"
            stopButton.isEnabled = true
            endpoint.stringValue = "AWS endpoint: http://localhost:\(servicePort)"
        case .failed(let m):
            status.stringValue = "⚠︎ \(m)"; button.title = "Stop to retry"
            stopButton.isEnabled = true
        }
        button.isEnabled = {
            if case .starting = st { return false }
            if case .running = st { return false }
            return true
        }()
    }

    func begin() {
        let kernel = resources.appendingPathComponent("vmlinux")
        let initrd = resources.appendingPathComponent("initrd.gz")
        guard FileManager.default.fileExists(atPath: kernel.path), FileManager.default.fileExists(atPath: initrd.path) else {
            render(.failed("guest kernel/initrd missing from app bundle")); return
        }
        vmc.state = .stopped
        vmc.start(kernel: kernel, initrd: initrd, workspace: workspaceMode)
    }

    @objc func toggle() {
        switch vmc.state {
        case .stopped: begin()
        case .failed: vmc.stop()
        default: break
        }
    }

    @objc func stopVM() {
        vmc.stop()
    }

    @objc func copyEnv() {
        let values = """
        export AWS_ENDPOINT_URL=http://localhost:\(servicePort)
        export AWS_ACCESS_KEY_ID=test
        export AWS_SECRET_ACCESS_KEY=test
        export AWS_DEFAULT_REGION=us-east-1
        """
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(values, forType: .string)
    }

    @objc func openGuide() {
        if let guideWindow {
            guideWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let guide = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 720),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        guide.title = "Localite — Getting started"
        guide.minSize = NSSize(width: 600, height: 500)

        let heading = NSTextField(labelWithString: "Connect your AWS project to Localite")
        heading.font = .systemFont(ofSize: 20, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: "Localite is a local AWS-compatible test endpoint. Your application runs on your Mac; its AWS SDK sends requests to the isolated Linux VM.")
        subtitle.font = .systemFont(ofSize: 13)
        subtitle.textColor = .secondaryLabelColor

        let copyEnvironment = NSButton(title: "Copy AWS environment", target: self, action: #selector(copyEnv))
        copyEnvironment.bezelStyle = .rounded
        let copyExample = NSButton(title: "Copy Python example", target: self, action: #selector(copyPythonExample))
        copyExample.bezelStyle = .rounded
        let actions = NSStackView(views: [copyEnvironment, copyExample])
        actions.orientation = .horizontal
        actions.alignment = .leading
        actions.spacing = 8

        let guideText = NSTextView(frame: .zero)
        guideText.isEditable = false
        guideText.isSelectable = true
        guideText.font = .systemFont(ofSize: 13)
        guideText.textColor = .labelColor
        guideText.backgroundColor = .textBackgroundColor
        guideText.textContainerInset = NSSize(width: 14, height: 14)
        guideText.isVerticallyResizable = true
        guideText.isHorizontallyResizable = false
        guideText.textContainer?.widthTracksTextView = true
        guideText.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        guideText.textStorage?.setAttributedString(Self.guideAttributedText())

        let scroll = NSScrollView()
        scroll.documentView = guideText
        scroll.hasVerticalScroller = true
        scroll.borderType = .lineBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        guide.contentView = content
        for view in [heading, subtitle, actions, scroll] {
            view.translatesAutoresizingMaskIntoConstraints = false
            content.addSubview(view)
        }
        NSLayoutConstraint.activate([
            heading.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
            heading.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
            heading.topAnchor.constraint(equalTo: content.topAnchor, constant: 18),
            subtitle.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            subtitle.trailingAnchor.constraint(equalTo: heading.trailingAnchor),
            subtitle.topAnchor.constraint(equalTo: heading.bottomAnchor, constant: 6),
            actions.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            actions.topAnchor.constraint(equalTo: subtitle.bottomAnchor, constant: 12),
            scroll.leadingAnchor.constraint(equalTo: heading.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: heading.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: actions.bottomAnchor, constant: 12),
            scroll.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -18)
        ])

        guide.center()
        guideWindow = guide
        guide.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc func copyPythonExample() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(Self.pythonExample, forType: .string)
    }

    private static let pythonExample = """
    import boto3

    s3 = boto3.client(
        "s3",
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    print(s3.list_buckets())
    """

    private static func guideAttributedText() -> NSAttributedString {
        let content = """
        ## 1. Start the local stack
        Localite starts its Apple Silicon Linux VM when the app opens. Wait until the main window says “Running · Moto AWS API” and shows http://localhost:4566. The endpoint exists only while the VM is running. Localite does not need Docker.

        ## 2. Point your tools at Localite (not AWS)
        Click “Copy AWS env”, open Terminal, and paste the exported variables into the same shell where you will run your app or tests:
            export AWS_ENDPOINT_URL=http://localhost:4566
            export AWS_ACCESS_KEY_ID=test
            export AWS_SECRET_ACCESS_KEY=test
            export AWS_DEFAULT_REGION=us-east-1

        These are fake local credentials. Verify the endpoint setting before running commands: without an explicit local endpoint, an AWS CLI or SDK may contact your configured AWS account instead. For AWS CLI commands, use --endpoint-url http://localhost:4566 as shown below. Never paste production credentials into Localite.

        ## 3. Make a first SDK request
        Install boto3 in your project environment with “python3 -m pip install boto3”. Click “Copy Python example” to copy a self-contained S3 client call. In your own app, either set AWS_ENDPOINT_URL as above or configure endpoint_url explicitly on each SDK client. Other languages use their normal SDK endpoint override.

        ## 4. Try the AWS CLI
        These commands create a local bucket, upload and list an object, then remove the test data:
            aws --endpoint-url http://localhost:4566 s3 mb s3://localite-demo
            printf 'hello from Localite\\n' > /tmp/localite-demo.txt
            aws --endpoint-url http://localhost:4566 s3 cp /tmp/localite-demo.txt s3://localite-demo/demo.txt
            aws --endpoint-url http://localhost:4566 s3 ls s3://localite-demo
            aws --endpoint-url http://localhost:4566 s3 rm s3://localite-demo/demo.txt
            aws --endpoint-url http://localhost:4566 s3 rb s3://localite-demo

        You can also use the AWS testing workbench: choose a service and operation, edit the JSON parameters, then click “Run AWS request”. “Browse resources” runs the collection-list request available for that service. The responses show HTTP status and the service response.

        ## 5. What has been exercised
        Localite ships the pinned ARM64 Moto server image inside the Linux VM. The image tag is 5.2.5, while its installed package metadata reports Moto 5.2.5.dev0. The checked-in boto3 smoke test has successfully exercised:
            S3: create/delete bucket; put/get/list/delete object.
            SQS: create/delete queue; send/receive/delete message.
            DynamoDB: create/delete table; put/get/update/query/scan item.
            IAM: create/get/list/delete user.
            STS: get caller identity.

        The workbench exposes these operations:
        S3: ListBuckets, CreateBucket, ListObjectsV2, PutObject, GetObject, DeleteObject, DeleteBucket.
        SQS: ListQueues, CreateQueue, GetQueueUrl, SendMessage, ReceiveMessage, DeleteMessage, DeleteQueue, PurgeQueue.
        DynamoDB: ListTables, CreateTable, DescribeTable, PutItem, GetItem, UpdateItem, Query, Scan, DeleteItem, DeleteTable.
        IAM: ListUsers, CreateUser, GetUser, DeleteUser.
        STS: GetCallerIdentity.

        This is a tested subset, not a promise of complete AWS or LocalStack compatibility. Moto supports more APIs, but Localite has not verified every service or operation. Lambda code execution is not provided. The local test credentials are not an IAM security boundary.

        ## 6. Project files and isolation
        “Import private project copy” creates a separate copy under ~/Library/Application Support/Localite/Workspaces and mounts that copy into the VM at /workspace; your original folder is not mounted. “Share folder” is a separate opt-in that gives the VM read/write access to the selected host folder. Stop the VM before changing its workspace.

        The workspace is file storage, not a development container or code runner. Your editor, CLI, and application run on macOS and connect to localhost:4566. The API server runs inside the Linux VM and is isolated from other host files except the workspace you selected.

        ## 7. Data lifetime and troubleshooting
        Emulator resources are in memory and reset when you stop Localite. Treat this as a disposable development/test stack, not a durable database or production service. The endpoint binds to host loopback only; other machines on your network cannot connect.

        If a request cannot connect, wait for the Running status, confirm Localite is still open, and check that another LocalStack/Localite process is not already using port 4566. If AWS CLI reaches AWS instead of Localite, stop and check its --endpoint-url argument. If an SDK reports missing credentials, use the test environment values above.

        ## Distribution status
        This app supports Apple Silicon Macs (macOS 12 or later). The current DMG is a local, ad-hoc-signed build; it is not notarized or published as a team-ready download. Before distributing it broadly, provide a Developer ID-signed and notarized release and pin/retest the bundled emulator version.
        """

        let result = NSMutableAttributedString()
        let bodyFont = NSFont.systemFont(ofSize: 13)
        let headingFont = NSFont.systemFont(ofSize: 15, weight: .semibold)
        let codeFont = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        for line in content.components(separatedBy: "\n") {
            let isHeading = line.hasPrefix("## ")
            let isCode = line.hasPrefix("    ")
            let paragraph = NSMutableParagraphStyle()
            paragraph.paragraphSpacing = isHeading ? 8 : 3
            paragraph.lineBreakMode = .byWordWrapping
            let text = isHeading ? String(line.dropFirst(3)) : (isCode ? String(line.dropFirst(4)) : line)
            let attributes: [NSAttributedString.Key: Any] = [
                .font: isHeading ? headingFont : (isCode ? codeFont : bodyFont),
                .foregroundColor: NSColor.labelColor,
                .paragraphStyle: paragraph
            ]
            result.append(NSAttributedString(string: text + "\n", attributes: attributes))
        }
        return result
    }

    @objc func importProject() {
        guard isStopped else { showStoppedNotice(); return }
        let panel = NSOpenPanel()
        panel.title = "Import a private project copy"
        panel.message = "Localite makes a separate private copy. The original folder is not mounted."
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let source = panel.url else { return }

        isImportingWorkspace = true
        updateWorkspaceControls()
        workspaceStatus.stringValue = "Importing a private copy…"
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let copy = try WorkspaceCopy.importProject(from: source)
                DispatchQueue.main.async {
                    self.isImportingWorkspace = false
                    self.workspaceWarning = nil
                    UserDefaults.standard.set(copy.path, forKey: "privateWorkspacePath")
                    UserDefaults.standard.removeObject(forKey: "privateWorkspaceDisk")
                    UserDefaults.standard.set("private", forKey: "workspaceMode")
                    self.workspaceMode = .privateCopy(copy)
                    self.updateWorkspaceLabel()
                    self.updateWorkspaceControls()
                }
            } catch {
                DispatchQueue.main.async {
                    self.isImportingWorkspace = false
                    self.workspaceStatus.stringValue = "Import failed"
                    self.updateWorkspaceControls()
                    self.showError("Could not import project", error.localizedDescription)
                }
            }
        }
    }

    @objc func shareFolder() {
        guard isStopped else { showStoppedNotice(); return }
        let warning = NSAlert()
        warning.messageText = "Share a host folder with the Linux guest?"
        warning.informativeText = "The guest will have read/write access to the folder you choose. This is not a private VM copy."
        warning.addButton(withTitle: "Choose shared folder")
        warning.addButton(withTitle: "Cancel")
        guard warning.runModal() == .alertFirstButtonReturn else { return }

        let panel = NSOpenPanel()
        panel.title = "Choose a folder to share with the guest"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        workspaceWarning = nil
        UserDefaults.standard.set(folder.path, forKey: "sharedWorkspaceFolder")
        UserDefaults.standard.set("shared", forKey: "workspaceMode")
        workspaceMode = .sharedFolder(folder)
        updateWorkspaceLabel()
    }

    @objc func usePrivateWorkspace() {
        guard isStopped else { showStoppedNotice(); return }
        guard let path = UserDefaults.standard.string(forKey: "privateWorkspacePath"),
              FileManager.default.fileExists(atPath: path) else {
            showError("No imported project", "Import a private project copy first.")
            return
        }
        workspaceWarning = nil
        UserDefaults.standard.set("private", forKey: "workspaceMode")
        workspaceMode = .privateCopy(URL(fileURLWithPath: path, isDirectory: true))
        updateWorkspaceLabel()
    }

    @objc func clearWorkspace() {
        guard isStopped else { showStoppedNotice(); return }
        workspaceWarning = nil
        UserDefaults.standard.set("none", forKey: "workspaceMode")
        workspaceMode = .none
        updateWorkspaceLabel()
    }

    @objc func serviceChanged() {
        guard let service = servicePicker.selectedItem?.title else { return }
        operationPicker.removeAllItems()
        operationPicker.addItems(withTitles: AWSWorkbench.operations[service] ?? [])
        operationChanged()
    }

    @objc func operationChanged() {
        guard let operation = operationPicker.selectedItem?.title else { return }
        parametersView.string = AWSWorkbench.defaultPayload(for: operation)
    }

    @objc func browseResources() {
        guard let service = servicePicker.selectedItem?.title,
              let operation = AWSWorkbench.browseOperation(for: service) else {
            responseView.string = "This emulator does not implement a collection-list operation for the selected service."
            return
        }
        operationPicker.selectItem(withTitle: operation)
        operationChanged()
        executeRequest(service: service, operation: operation)
    }

    @objc func runRequest() {
        guard let service = servicePicker.selectedItem?.title,
              let operation = operationPicker.selectedItem?.title else { return }
        executeRequest(service: service, operation: operation)
    }

    private func executeRequest(service: String, operation: String) {
        if case .running = vmc.state {} else {
            responseView.string = "Start the Linux sandbox before sending AWS requests."
            return
        }
        runButton.isEnabled = false
        browseButton.isEnabled = false
        responseView.string = "Sending \(service).\(operation)…"
        AWSWorkbench.perform(service: service, operation: operation, payloadText: parametersView.string) { [weak self] result in
            DispatchQueue.main.async {
                self?.runButton.isEnabled = true
                self?.browseButton.isEnabled = true
                switch result {
                case .success(let response): self?.responseView.string = response
                case .failure(let error): self?.responseView.string = "Request failed\n\(error.localizedDescription)"
                }
            }
        }
    }

    private var isStopped: Bool {
        if case .stopped = vmc.state { return true }
        return false
    }

    private func loadWorkspace() {
        workspaceWarning = nil
        switch UserDefaults.standard.string(forKey: "workspaceMode") ?? "none" {
        case "private":
            if let path = UserDefaults.standard.string(forKey: "privateWorkspacePath"),
               FileManager.default.fileExists(atPath: path) {
                workspaceMode = .privateCopy(URL(fileURLWithPath: path, isDirectory: true))
            } else if UserDefaults.standard.string(forKey: "privateWorkspaceDisk") != nil {
                workspaceWarning = "Re-import the saved FAT32 workspace to use it with this build"
            } else {
                workspaceWarning = "Saved private workspace copy is missing"
            }
        case "shared":
            if let path = UserDefaults.standard.string(forKey: "sharedWorkspaceFolder"),
               FileManager.default.fileExists(atPath: path) {
                workspaceMode = .sharedFolder(URL(fileURLWithPath: path, isDirectory: true))
            } else {
                workspaceWarning = "Previously shared host folder is unavailable"
            }
        default:
            workspaceMode = .none
        }
        updateWorkspaceLabel()
    }

    private func updateWorkspaceLabel() {
        if let workspaceWarning {
            workspaceStatus.stringValue = workspaceWarning
            return
        }
        switch workspaceMode {
        case .none:
            workspaceStatus.stringValue = "No project workspace selected"
        case .privateCopy(let url):
            workspaceStatus.stringValue = "Private VM copy: \(url.lastPathComponent)"
        case .sharedFolder(let url):
            workspaceStatus.stringValue = "Shared read/write host folder: \(url.path)"
        }
    }

    private func updateWorkspaceControls() {
        let enabled = isStopped && !isImportingWorkspace
        importButton.isEnabled = enabled
        shareButton.isEnabled = enabled
        privateButton.isEnabled = enabled
        clearWorkspaceButton.isEnabled = enabled
    }

    private func showStoppedNotice() {
        showError("Stop the sandbox first", "Workspace settings can only be changed while the Linux sandbox is stopped.")
    }

    private func showError(_ title: String, _ message: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func configureTextView(_ view: NSTextView, placeholder: String) {
        view.isEditable = true
        view.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        view.textColor = .black
        view.string = ""
        view.backgroundColor = NSColor(white: 0.97, alpha: 1)
        view.textContainerInset = NSSize(width: 8, height: 8)
        view.toolTip = placeholder
    }

    private func textScrollView(_ view: NSTextView, height: CGFloat) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.documentView = view
        scroll.hasVerticalScroller = true
        scroll.borderType = .lineBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
        return scroll
    }

    func windowWillClose(_ n: Notification) { vmc.stop(); NSApp.terminate(nil) }
    func applicationWillTerminate(_ n: Notification) { vmc.stop() }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()

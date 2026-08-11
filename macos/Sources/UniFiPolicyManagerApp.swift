import SwiftUI

@main
struct UniFiPolicyManagerApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 1040, minHeight: 700)
        }
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("策略") {
                Button("刷新全部策略") { model.refreshAll() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(!model.connected || model.busy)
                Button("导出当前基线…") { model.exportBaseline() }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(!model.connected)
            }
        }
    }
}

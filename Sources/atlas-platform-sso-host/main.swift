import AppKit

// The container app of the Platform SSO extension. An app extension has to ship inside an app; this one has no window of its own:
// the system loads the extension (embedded in PlugIns/) once an MDM Extensible SSO payload names it.
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
app.run()

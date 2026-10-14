import Foundation
import Testing
@testable import CorrelatorCore

@Test func emptyUSBInventoryIsValid() throws {
    #expect(try parseAppleUSBSerials(Data()).isEmpty)
    let emptyArray = "<?xml version=\"1.0\"?><plist version=\"1.0\"><array/></plist>"
    #expect(try parseAppleUSBSerials(Data(emptyArray.utf8)).isEmpty)
}

@Test func nestedUSBInventoryRequiresAppleVendorAndDeduplicatesSerials() throws {
    let xml = """
    <?xml version="1.0"?><plist version="1.0"><array><dict>
      <key>idVendor</key><integer>4369</integer>
      <key>USB Serial Number</key><string>other-vendor</string>
      <key>IORegistryEntryChildren</key><array>
        <dict><key>idVendor</key><integer>1452</integer>
          <key>USB Serial Number</key><string>apple-device</string>
          <key>IORegistryEntryName</key><string>Unrelated registry property</string></dict>
        <dict><key>idVendor</key><integer>1452</integer>
          <key>USB Serial Number</key><string>apple-device</string></dict>
        <dict><key>USB Serial Number</key><string>unknown-vendor</string></dict>
      </array>
    </dict></array></plist>
    """
    #expect(try parseAppleUSBSerials(Data(xml.utf8)) == ["apple-device"])
}

@Test func malformedUSBInventoryStillFails() {
    let invalid = [
        " ",
        "\n\t",
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><array>",
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>",
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><array><dict><key>idVendor</key><string>1452</string></dict></array></plist>",
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><array><dict><key>USB Serial Number</key><integer>1</integer></dict></array></plist>"
    ]
    for xml in invalid {
        #expect(throws: AnalysisError.self) { try parseAppleUSBSerials(Data(xml.utf8)) }
    }
}

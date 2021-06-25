//
//  TestNxosV6.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 8/20/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest
@testable import AclAnalyzerKit

class TestNxosV6: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testNxos1() {
        let sample = """
        ipv6 access-list acl-120
          permit tcp 2001:0db8:85a3::/48 2001:0db8:be03:2112::/64
          permit udp 2001:0db8:85a3::/48 2001:0db8:be03:2112::/64
          permit tcp 2001:0db8:69f2::/48 2001:0db8:be03:2112::/64
          permit udp 2001:0db8:69f2::/48 2001:0db8:be03:2112::/64
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
                let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a4::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv6)!
                let result = acl.analyze(socket: socket)
                XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2113::".ipv6address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos2() {
        let sample = """
        object-group ipv6 address ipv6-addr-group-A7
            host 2001:db8:0:3ab0::1
            2001:0db8:85a3::/48
        object-group ip port WEB
            eq 80
            eq 443
            range 8000 8999
        ipv6 access-list L3Port
            permit tcp addrgroup ipv6-addr-group-A7 portgroup WEB any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 81, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 8000, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 7999, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 443, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a4::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 443, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos3() {
        let sample = """
        object-group ipv6 address ipv6-addr-group-A7
            10 host 2001:db8:0:3ab0::1
            20 2001:0db8:85a3::/48
        object-group ip port WEB
            10 eq 80
            20 eq 443
            30 range 8000 8999
        ipv6 access-list L3Port
            10 permit tcp addrgroup ipv6-addr-group-A7 portgroup WEB any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 81, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 8000, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:db8:0:3ab0::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 7999, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 443, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a4::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 443, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxosInvalidPortGroup() {
        let sample = """
        object-group ipv6 address ipv6-addr-group-A7
            10 host 2001:db8:0:3ab0::1
            20 2001:0db8:85a3::/48
        object-group ip port WEB
        ipv6 access-list L3Port
            10 permit tcp addrgroup ipv6-addr-group-A7 portgroup WEB any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxosInvalidPortGroup2() {
        let sample = """
        object-group ipv6 address ipv6-addr-group-A7
            10 host 2001:db8:0:3ab0::1
            20 2001:0db8:85a3::/48
        object-group ip port WEB
        ipv6 access-list L3Port
            10 permit tcp addrgroup ipv6-addr-group-A7 any portgroup WEB
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxos4() {
        let sample = """
        ipv6 access-list acl-120
        permit tcp 2001:0db8:85a3::/48 2001:0db8:be03:2112::/64
        permit udp 2001:0db8:85a3::/48 2001:0db8:be03:2112::/64
        permit tcp 2001:0db8:69f2::/48 2001:0db8:be03:2112::/64
        permit udp 2001:0db8:69f2::/48 2001:0db8:be03:2112::/64
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 4)

        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a4::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2113::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2112:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a2:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2112:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2111:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a4::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2113::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2112:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a2:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2112:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3:ffff:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "2001:0db8:be03:2111:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    func testNxos5() {
        let sample = """
        ipv6 access-list v6_BGP_ACL
        permit tcp any eq bgp any
        permit tcp any any eq bgp
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 179, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 178, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 179, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 180, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos6() {
        let sample = """
        ipv6 access-list copp-system-p-acl-bgp
        permit tcp any gt 1024 any eq bgp
        permit tcp any eq bgp any gt 1024
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 179, destinationPort: 1025, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 178, destinationPort: 1025, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 1025, destinationPort: 179, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 1025, destinationPort: 180, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 179, destinationPort: 1024, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 1024, destinationPort: 179, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 0, destinationPort: 179, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos7() {
        let sample = """
        ipv6 access-list copp-system-p-acl-rip6
        permit udp any ff02::9/128 eq 521
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "ff02::9".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "ff02::9".ipv6address!, sourcePort: 179, destinationPort: 522, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "ff02::9".ipv6address!, sourcePort: 179, destinationPort: 520, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "ff02::a".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "ff02::9".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "ff02::8".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    func testNxos8() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        10 permit tcp 2001:504:2f::/64 eq bgp 2001:504:2f::/64
        20 permit tcp 2001:504:2f::/64 2001:504:2f::/64 eq bgp
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:504:2f::".ipv6address!, destinationIp: "2001:504:2f::".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:504:2f::".ipv6address!, destinationIp: "2001:504:2f::".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:504:2f::".ipv6address!, destinationIp: "2001:504:30::".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:504:30::".ipv6address!, destinationIp: "2001:504:2f::".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:504:2e:f:ff:fff::ffff".ipv6address!, destinationIp: "2001:504:2f::".ipv6address!, sourcePort: 179, destinationPort: 521, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos9() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 range 54104 60990 8199:830a:da13:2936:00af:d493:1254:9200/119 eq 54178 established
        permit tcp 7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000/113 range 19471 56308 65df:5c00:926d:c359:2810:0000:0000:0000/76 range 1119 25347 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 19471, destinationPort: 1119, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 19471, destinationPort: 1119, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 19470, destinationPort: 1119, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 56308, destinationPort: 1119, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 56309, destinationPort: 1119, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 56308, destinationPort: 25347, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 56308, destinationPort: 25348, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:8000".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 19471, destinationPort: 25347, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "7129:6ae6:2db5:0af2:9c4d:f46b:1225:7fff".ipv6address!, destinationIp: "65df:5c00:926d:c359:2810:0000:0000:0000".ipv6address!, sourcePort: 19471, destinationPort: 25347, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }
    func testNxos10() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 range 54104 60990 8199:830a:da13:2936:00af:d493:1254:9200/119 eq 54178 established
        permit tcp 7129:6ae6:2db5:0af2:9c4d:f46b:1225:0000/113 range 19471 56308 65df:5c00:926d:c359:2810:0000:0000:0000/76 range 1119 25347 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54178, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54179, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54177, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54103, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 60990, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 60991, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos11() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit udp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 range 54104 60990 8199:830a:da13:2936:00af:d493:1254:9200/119 eq 54178 established
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxos12() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 range 54104 65536 8199:830a:da13:2936:00af:d493:1254:9200/119 eq 54178 established
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxos13() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 range 54104 60990 8199:830a:da13:2936:00af:d493:1254:9200/119 eq 65536
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxos14() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 range 54104 60990 8199:830a:da13:2936:00af:d493:1254:9200/129 eq 65536
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxos15() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 lt 54104 8199:830a:da13:2936:00af:d493:1254:9200/119 gt 54178
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54103, destinationPort: 54179, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54179, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54103, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos16() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 gt 54104 8199:830a:da13:2936:00af:d493:1254:9200/119 lt 54178
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54105, destinationPort: 54177, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54177, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54105, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos17() {
        let sample = """
        ipv6 access-list MATCH-BGP-V6
        permit tcp 51d0:5fdd:b320:b271:8c90:a4f6:956a:d800/119 neq 54104 8199:830a:da13:2936:00af:d493:1254:9200/119 neq 54178
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54103, destinationPort: 54177, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54104, destinationPort: 54177, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54105, destinationPort: 54177, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54103, destinationPort: 54178, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "51d0:5fdd:b320:b271:8c90:a4f6:956a:d800".ipv6address!, destinationIp: "8199:830a:da13:2936:00af:d493:1254:9200".ipv6address!, sourcePort: 54103, destinationPort: 54179, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }
    func testNxos18() {
        let sample = """
        ipv6 access-list acl-120
          permit tcp any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testNxos19() {
        let sample = """
        ipv6 access-list acl-120
          permit tcp any any established
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxosv6, delegate: nil, delegateWindow: nil)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 33, destinationPort: 80, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
}

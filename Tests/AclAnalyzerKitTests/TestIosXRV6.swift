//
//  TestIosXRV6.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 9/1/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest
@testable import AclAnalyzerKit

class TestIosXRV6: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testIosXrSix1() {
        let sample = """
        ipv6 access-list acl-120
        permit 2001:0db8:85a3::/48
        permit tcp 2001:0db9:85a3::/48 2001:0db8:be03:2112::/64
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:85a2:ffff:ffff:ffff:ffff::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db9:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "2001:0db9:85a3::".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXrSix2() {
        let sample = """
        object-group  network ipv6 netobject2
            2001::0/128
        ipv6 access-list scaled_acl2
        10 permit ipv6 net-group netobject2 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001::0".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    func testIosXrSix3() {
        let sample = """
        object-group network ipv6 netobj1
            description my-network-object
            host 2001:DB8:1::1
        ipv6 access-list scaled_acl2
        10 permit ipv6 net-group netobj1 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::2".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::0".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    func testIosXrSix4() {
        let sample = """
        ipv6 access-list v6_abf
        10 permit ipv6 host 100:1:1:2:3::1 host 10:11:12::2
        40 permit ipv6 host 100:1:1:2:3::1 host 10:11:12::3
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "100:1:1:2:3::1".ipv6address!, destinationIp: "10:11:12::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "100:1:1:2:3::1".ipv6address!, destinationIp: "10:11:12::3".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "100:1:1:2:3::2".ipv6address!, destinationIp: "10:11:12::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "100:1:1:2:3::1".ipv6address!, destinationIp: "10:11:12::4".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXrSix5() {
        let sample = """
        ipv6 access-list aclv6
        10 permit ipv6 1111:6666::2/128 1111:7777::2/128
        30 permit tcp host 1111:4444::2 eq 100 host 1111:5555::2 eq 10
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:6666::2".ipv6address!, destinationIp: "1111:7777::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:6666::3".ipv6address!, destinationIp: "1111:7777::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:6666::2".ipv6address!, destinationIp: "1111:7777::1".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:4444::2".ipv6address!, destinationIp: "1111:5555::2".ipv6address!, sourcePort: 100, destinationPort: 10, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:4444::2".ipv6address!, destinationIp: "1111:5555::2".ipv6address!, sourcePort: 101, destinationPort: 10, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:4444::2".ipv6address!, destinationIp: "1111:5555::2".ipv6address!, sourcePort: 100, destinationPort: 9, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    func testIosXrSix6() {
        let sample = """
        ipv6 access-list Internetfilter
        10 permit ipv6 3333:1:2:3::/64 any
        20 permit ipv6 4444:1:2:3::/64 any
        30 permit ipv6 5555:1:2:3::/64 any
        39 remark Permit BGP traffic from a given host
        40 permit tcp host 6666:1:2:3::10 eq bgp host 7777:1:2:3::20 range 1300 1400
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 4)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "6666:1:2:3::10".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 179, destinationPort: 1300, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "6666:1:2:3::10".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 180, destinationPort: 1300, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "6666:1:2:3::10".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 179, destinationPort: 1401, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "3333:1:2:3::".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 179, destinationPort: 1300, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "3333:1:2:3:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 179, destinationPort: 1300, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "3333:1:2:4::".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 179, destinationPort: 1300, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "3333:1:2:2:ffff:ffff:ffff:ffff".ipv6address!, destinationIp: "7777:1:2:3::20".ipv6address!, sourcePort: 179, destinationPort: 1300, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXrSix7() {
        let sample = """
        object-group network ipv6 netobj1
            description my-network-object
            range 2001:DB8:1::1 2001:DB8:1::f
        ipv6 access-list scaled_acl2
        10 permit ipv6 net-group netobj1 any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::1".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::f".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::0".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:DB8:1::10".ipv6address!, destinationIp: "2001:0db8:be03:2112::".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXrSix8() {
        let sample = """
        ipv6 access-list aclv6
        10 permit tcp any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:6666::2".ipv6address!, destinationIp: "1111:7777::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1111:6666::2".ipv6address!, destinationIp: "1111:7777::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXrSix9() {
        let sample = """
        ipv6 access-list aclv6
        10 permit tcp any any established
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1111:6666::2".ipv6address!, destinationIp: "1111:7777::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: true, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "1111:6666::2".ipv6address!, destinationIp: "1111:7777::2".ipv6address!, sourcePort: 80, destinationPort: 80, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testIosXrSix10() {
        let sample = """
        ipv6 access-list aclv6
        1 permit 17 efb6:e60d:7f7c:e8e2:497a:b2e6:1c00:0000/102 neq 26594 8fb7:837a:4690:a946:be32:288d:8000:0000/97 eq 15741
        """
        let acl = AccessList(sourceText: sample, deviceType: .iosxrv6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "efb6:e60d:7f7c:e8e2:497a:b2e6:1c00:0000".ipv6address!, destinationIp: "8fb7:837a:4690:a946:be32:288d:8000:0000".ipv6address!, sourcePort: 80, destinationPort: 15741, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "efb6:e60d:7f7c:e8e2:497a:b2e6:1c00:0000".ipv6address!, destinationIp: "8fb7:837a:4690:a946:be32:288d:8000:0000".ipv6address!, sourcePort: 80, destinationPort: 15741, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
}

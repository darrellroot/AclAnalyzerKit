//
//  TestAristaIPv6.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 10/22/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest
@testable import AclAnalyzerKit

class TestAristaIPv6: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testArista1() {
        let sample = """
        IP Access List test1
        10 permit ipv6 2001:0db8:1b04:3::/64 any
        20 permit ipv6 2620:0db8:3:4::/64 host 3ffe:1111::abcd
        30 permit ipv6 host 3fff:1111::1 host 3fff:1111::2 log
        40 deny ipv6 any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .aristav6, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 4)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:1b04:3:1111:2222:3333:4444".ipv6address!, destinationIp: "::2".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2001:0db8:1b04:4:1111:2222:3333:4444".ipv6address!, destinationIp: "::2".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "2620:0db8:3:4:1111:2222:3333:4444".ipv6address!, destinationIp: "3ffe:1111::abcd".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "3fff:1111::1".ipv6address!, destinationIp: "3fff:1111::2".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }

    }

    func testArista2() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit tcp 1234:5678:9abc:def0:0123:4567::/96 1234:5678:9abc:def0:0123:4567:89ab::/112 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:4567:89ab:cdef".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:ffff".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:4567:89ab:cdef".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ac:0000".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:4568:89ab:cdef".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:ffff".ipv6address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
        
    func testArista3() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit tcp 1234:5678:9abc:def0:0123::/80 eq 80 1234:5678:9abc:def0:0123:4567:89ab:3000/116 eq 90
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:ffff:ffff:ffff".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:3000".ipv6address!, sourcePort: 80, destinationPort: 90, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0124::".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:3000".ipv6address!, sourcePort: 80, destinationPort: 90, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:ffff:ffff:ffff".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:2fff".ipv6address!, sourcePort: 80, destinationPort: 90, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:ffff:ffff:ffff".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:3000".ipv6address!, sourcePort: 81, destinationPort: 90, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1234:5678:9abc:def0:0123:ffff:ffff:ffff".ipv6address!, destinationIp: "1234:5678:9abc:def0:0123:4567:89ab:3000".ipv6address!, sourcePort: 80, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    func testArista4() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c/127 gt 80 78d9:48bc:ea48:df8c:a5e8:e569:4146:a000/116 lt 90
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 81, destinationPort: 89, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13d".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 81, destinationPort: 89, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13b".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 81, destinationPort: 89, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:9fff".ipv6address!, sourcePort: 81, destinationPort: 89, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 80, destinationPort: 89, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 81, destinationPort: 90, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 81, destinationPort: 89, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    
    func testArista4a() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c/127 lt 80 78d9:48bc:ea48:df8c:a5e8:e569:4146:a000/116 gt 90
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 79, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13d".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 79, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13b".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 79, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:9fff".ipv6address!, sourcePort: 79, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 80, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 79, destinationPort: 90, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "84d2:e3ba:20dc:de7f:e8be:9c9d:dfb5:b13c".ipv6address!, destinationIp: "78d9:48bc:ea48:df8c:a5e8:e569:4146:a000".ipv6address!, sourcePort: 79, destinationPort: 91, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }


    func testArista5() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp f27b:1af0:95bb:f960:cf43:ca11:3880:0000/106 range 10 20 1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00/119 range 30 40 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00".ipv6address!, sourcePort: 19, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00".ipv6address!, sourcePort: 21, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00".ipv6address!, sourcePort: 10, destinationPort: 40, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00".ipv6address!, sourcePort: 10, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7a00".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7bff".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:7c00".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "f27b:1af0:95bb:f960:cf43:ca11:3880:0000".ipv6address!, destinationIp: "1dd1:8d40:ab39:5521:a4c0:1bdf:3ced:79ff".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }

    func testArista6() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 148e:1e90:866d:2f88:8cf9:8000:0000:0000/83 eq 10 20 30 40 62b2:7558:8887:e04c:5955:fd60:7e9e:8000/115 eq 30 40 50 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:9fff:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:a000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 11, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 40, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 41, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 50, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 51, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 40, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }

    func testArista6a() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 148e:1e90:866d:2f88:8cf9:8000:0000:0000/83 eq 20 30 10 40 62b2:7558:8887:e04c:5955:fd60:7e9e:8000/115 eq 50 40 30 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:9fff:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:a000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 11, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 40, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 41, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 50, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 51, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 40, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
    }

    func testArista7() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 148e:1e90:866d:2f88:8cf9:8000:0000:0000/83 neq 10 20 30 40 62b2:7558:8887:e04c:5955:fd60:7e9e:8000/115 neq 30 40 50 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 9, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 9, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 11, destinationPort: 31, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 21, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 30, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 31, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 41, destinationPort: 51, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 40, destinationPort: 51, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }

    }
    
    func testArista7a() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 148e:1e90:866d:2f88:8cf9:8000:0000:0000/83 neq 30 40 10 20 62b2:7558:8887:e04c:5955:fd60:7e9e:8000/115 neq 50 30 40 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 9, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 10, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 9, destinationPort: 30, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 11, destinationPort: 31, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 21, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 30, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 31, destinationPort: 41, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 41, destinationPort: 51, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "148e:1e90:866d:2f88:8cf9:8000:0000:0000".ipv6address!, destinationIp: "62b2:7558:8887:e04c:5955:fd60:7e9e:8000".ipv6address!, sourcePort: 40, destinationPort: 51, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }


    func testArista9() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 998c:3073:19f9:6e1d:2e4b:55b2:8000:0000/97 neq 0 8283:668f:0000:0000:0000:0000:0000:0000/32 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668f::".ipv6address!, sourcePort: 1, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668f::".ipv6address!, sourcePort: 0, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668f:ffff:ffff:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 1, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668e:ffff:ffff:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 1, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testArista9a() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 998c:3073:19f9:6e1d:2e4b:55b2:8000:0000/97 neq 65535 8283:668f:0000:0000:0000:0000:0000:0000/32 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668f::".ipv6address!, sourcePort: 65534, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668f::".ipv6address!, sourcePort: 65535, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668f:ffff:ffff:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 1, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "998c:3073:19f9:6e1d:2e4b:55b2:8000::".ipv6address!, destinationIp: "8283:668e:ffff:ffff:ffff:ffff:ffff:ffff".ipv6address!, sourcePort: 1, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testArista11() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0/125 neq 1 2 3 4 5 6 7 8 9 10 d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000/112 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 11, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 10, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 65535, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 0, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 1, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testArista12() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0/125 neq 1 2 3 4 5 6 7 8 9 10 11 d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000/112 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 11, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testArista13() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0/125 d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000/112 neq 1 2 3 4 5 6 7 8 9 10 11
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "c318:533c:0591:89d9:2cd5:7df1:7bc8:dfb0".ipv6address!, destinationIp: "d132:c609:98d7:0312:6ac2:aa9e:c4dc:0000".ipv6address!, sourcePort: 11, destinationPort: 29, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    
    func testArista15() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit udp 6800::/5 b01e:f017:aceb:93d4:5e07:9563:ef25:e400/120 neq 1 2 3 4 5 6 7 8 9 65535 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "6800::".ipv6address!, destinationIp: "b01e:f017:aceb:93d4:5e07:9563:ef25:e400".ipv6address!, sourcePort: 65534, destinationPort: 65534, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "6800::".ipv6address!, destinationIp: "b01e:f017:aceb:93d4:5e07:9563:ef25:e400".ipv6address!, sourcePort: 65534, destinationPort: 65535, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "6800::".ipv6address!, destinationIp: "b01e:f017:aceb:93d4:5e07:9563:ef25:e400".ipv6address!, sourcePort: 65534, destinationPort: 0, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "6800::".ipv6address!, destinationIp: "b01e:f017:aceb:93d4:5e07:9563:ef25:e400".ipv6address!, sourcePort: 65534, destinationPort: 1, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "67ff::".ipv6address!, destinationIp: "b01e:f017:aceb:93d4:5e07:9563:ef25:e400".ipv6address!, sourcePort: 65534, destinationPort: 65534, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
    func testArista16() {
        let sample = """
        IP Access List default-control-plane-acl
        10 permit ipv6 6800::/5 b01e:f017:aceb:93d4:5e07:9563:ef25:e400/120 neq 1 2 3 4 5 6 7 8 9 65535 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .arista, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "6800::".ipv6address!, destinationIp: "b01e:f017:aceb:93d4:5e07:9563:ef25:e400".ipv6address!, sourcePort: 65534, destinationPort: 65534, established: false, ipVersion: .IPv6)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result == .deny)
        }
    }
}

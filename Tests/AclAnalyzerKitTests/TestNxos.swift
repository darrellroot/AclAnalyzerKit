//
//  testNxos.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 7/12/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest
@testable import AclAnalyzerKit

class TestNxos: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testCidr1() {
        let ipRange = IpRange(cidr: "131.252.209.0/24")!
        XCTAssert(ipRange.bitAligned == true)
        XCTAssert(ipRange.minIp == "131.252.209.0".ipv4address)
        XCTAssert(ipRange.maxIp == "131.252.209.255".ipv4address)
    }
    func testCidr2() {
        let ipRange = IpRange(cidr: "131.252.209.12/24")!
        XCTAssert(ipRange.bitAligned == false)
        XCTAssert(ipRange.minIp == "131.252.209.0".ipv4address)
        XCTAssert(ipRange.maxIp == "131.252.209.255".ipv4address)
    }
    func testCidr3() {
        let ipRange = IpRange(cidr: "131.252.209.18/31")!
        XCTAssert(ipRange.bitAligned == true)
        XCTAssert(ipRange.minIp == "131.252.209.18".ipv4address)
        XCTAssert(ipRange.maxIp == "131.252.209.19".ipv4address)
    }

    func testNxos1() {
        let sample = """
        ip access-list bob
            10 permit ip 192.168.2.0/24 any
            20 permit tcp 131.252.209.0/24 10.24.30.0/23 eq 80
            30 permit udp 20.20.0.0/14 range 10 20 10.30.128.64/29 eq 50
            40 permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 49, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
        let socket4 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 15, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .permit)
        let socket5 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 9, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .deny)
    }
    
    func testNxosProtocolNumbered1() {
        let line1 = "permit 6 131.252.209.18/31 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 != nil)
    }

    func testNxosProtocolNumbered2() {
        let line1 = "permit 256 131.252.209.18/31 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 == nil)
    }


    func testNxos2() {
        let sample = """
        ip access-list bob
            permit ip 192.168.2.0/24 any
            permit tcp 131.252.209.0/24 10.24.30.0/23 eq 80
            permit udp 20.20.0.0/14 range 10 20 10.30.128.64/29 eq 50
            permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
    }
    
    func testNxos3() {
        let sample = """
        ip access-list bob
            10 permit ip 192.168.2.0/24 any established
            15 permit tcp 192.168.3.0/24 any established
            20 permit tcp 131.252.209.0/24 10.24.30.0/23 eq www
            30 permit udp 20.20.0.0/14 range domain bootps 10.30.128.64/29 eq 50
            40 permit udp 30.20.0.0/14 gt 20 10.30.128.64/29 neq 50 log
            statistics per entry
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket1a = Socket(ipProtocol: 6, sourceIp: "131.252.209.17".ipv4address!, destinationIp: "10.24.31.3".ipv4address!, sourcePort: 33, destinationPort: 81, established: false, ipVersion: .IPv4)!
        let result1a = acl.analyze(socket: socket1a)
        XCTAssert(result1a == .deny)
        let socket2 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 49, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        let socket3 = Socket(ipProtocol: 17, sourceIp: "30.21.3.17".ipv4address!, destinationIp: "10.30.128.65".ipv4address!, sourcePort: 50, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)
        let socket4 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 53, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .permit)
        let socket5 = Socket(ipProtocol: 17, sourceIp: "20.22.1.7".ipv4address!, destinationIp: "10.30.128.69".ipv4address!, sourcePort: 52, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .deny)
        let socket6 = Socket(ipProtocol: 6, sourceIp: "192.168.3.3".ipv4address!, destinationIp: "4.4.4.4".ipv4address!, sourcePort: 52, destinationPort: 50, established: false, ipVersion: .IPv4)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6 == .deny)
        let socket7 = Socket(ipProtocol: 6, sourceIp: "192.168.3.3".ipv4address!, destinationIp: "4.4.4.4".ipv4address!, sourcePort: 52, destinationPort: 50, established: true, ipVersion: .IPv4)!
        let result7 = acl.analyze(socket: socket7)
        XCTAssert(result7 == .permit)
        let socket8 = Socket(ipProtocol: 6, sourceIp: "192.168.2.3".ipv4address!, destinationIp: "4.4.4.4".ipv4address!, sourcePort: 52, destinationPort: 50, established: true, ipVersion: .IPv4)!
        let result8 = acl.analyze(socket: socket8)
        XCTAssert(result8 == .deny)
    }
    
    func testNxosCcierants1() {
        let sample = """
            1 remark 200,000 hits! Yay!
            10 permit tcp any any eq 22
            17 deny ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)

        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.99.32.6".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)

        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.99.32.6".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }

    
    func testNxosCcierants2() {
        let sample = """
            statistics per-entry
            1 remark 200,000 hits! Yay!
            2 deny icmp 10.0.0.132/32 10.0.0.3/32 log
            3 deny icmp 10.0.0.132/32 any log
            10 permit tcp any any eq 22
            17 deny ip any any
            20 deny ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 5)

        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.0.0.132".ipv4address!, destinationIp: "10.0.0.3".ipv4address!, sourcePort: 22, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)

        let socket2 = Socket(ipProtocol: 17, sourceIp: "10.0.0.132".ipv4address!, destinationIp: "10.0.0.3".ipv4address!, sourcePort: 22, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

    }
    
    func testNxos4() {
        let sample = """
        IP access list TEST
          10 deny ip any 11.0.0.2/32 log
          20 permit ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 2)

        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 22, destinationPort: 22, established: true, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .deny)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "11.0.0.3".ipv4address!, sourcePort: 22, destinationPort: 22, established: true, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
    }
    
    func testNxos5() {
        let sample = """
IPV4 ACL TACACS
statistics per-entry
10 permit tcp any any eq tacacs
20 permit tcp any eq tacacs any
30 permit udp any any eq 1812
40 permit udp any any eq 1813
50 permit udp any any eq 1645
60 permit udp any any eq 1646
70 permit udp any eq 1812 any
80 permit udp any eq 1813 any
90 permit udp any eq 1645 any
100 permit udp any eq 1646 any
110 permit icmp any any
120 deny ip any any
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 12)

        let socket1 = Socket(ipProtocol: 17, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 1812, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)

        let socket2 = Socket(ipProtocol: 17, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 1811, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
    }
    
    func testNxosObject1() {
        let sample = """
object-group ip address SERVERS
    10 host 1.1.1.101
    20 10.0.0.0/24
    30 11.0.0.0 0.0.255.255
object-group ip port WEB
    10 eq 80
    20 eq 443
    30 range 8000 8999
ip access-list L3Port
    10 permit tcp addrgroup SERVERS portgroup WEB any
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "11.0.37.45".ipv4address!, destinationIp: "12.0.0.2".ipv4address!, sourcePort: 80, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "11.1.0.0".ipv4address!, destinationIp: "12.0.0.2".ipv4address!, sourcePort: 80, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

    }
    
    // in below example 11-net is incorrect
    func testNxosObjectWrong1() {
        let sample = """
object-group ip address SERVERS
    10 host 1.1.1.101
    20 10.0.0.0/24
    30 11.0.0.0 255.255.0.0
object-group ip port WEB
    10 eq 80
    20 eq 443
    30 range 8000 8999
ip access-list L3Port
    10 permit tcp addrgroup SERVERS portgroup WEB any
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        XCTAssert(acl.objectGroupNetworks["servers"]?.ipRanges.count == 2)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "11.0.37.45".ipv4address!, destinationIp: "12.0.0.2".ipv4address!, sourcePort: 80, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .deny)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "12.0.0.2".ipv4address!, sourcePort: 80, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        
    }

    func testNxosObjectPort1() {
        let sample = """
object-group ip address SERVERS
    10 host 1.1.1.101
    20 10.0.0.0/24
    30 11.0.0.0 255.255.0.0
object-group ip port WEB
    10 eq 80
    20 eq 443
    30 range 8000 8999
ip access-list L3Port
    10 permit tcp addrgroup SERVERS portgroup WEB addrgroup SERVERS portgroup WEB log
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "11.0.37.45".ipv4address!, destinationIp: "1.1.1.101".ipv4address!, sourcePort: 80, destinationPort: 8999, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .deny)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "11.0.37.45".ipv4address!, destinationIp: "1.1.1.101".ipv4address!, sourcePort: 80, destinationPort: 9000, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

    }
    func testNxosCcieMcgee1() {
        let sample = """
object-group ip address SERVERS
    10 host 1.1.1.101
    20 10.0.0.0/24
object-group ip port WEB
    10 eq 80
    20 eq 443
    30 range 8000 8999
ip access-list L3Port
    10 permit tcp addrgroup SERVERS portgroup WEB any
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 80, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)

        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 7999, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

        let socket3 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 8000, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)

    }
    
    func testNxosObjectPortInvalid() {
        let sample = """
object-group ip address SERVERS
    10 host 1.1.1.101
    20 10.0.0.0/24
    30 11.0.0.0 255.255.0.0
object-group ip port WEB
ip access-list L3Port
    10 permit tcp addrgroup SERVERS addrgroup SERVERS portgroup WEB log
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }
    func testNxosObjectPortInvalid2() {
        let sample = """
object-group ip address SERVERS
    10 host 1.1.1.101
    20 10.0.0.0/24
    30 11.0.0.0 255.255.0.0
object-group ip port WEB
ip access-list L3Port
    10 permit tcp addrgroup SERVERS portgroup WEB addrgroup SERVERS log
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 0)
    }

    
    func testNxosCcieMcgeeWithSpaces() {
        let sample = """
object-group  ip  address  SERVERS
    10 host  1.1.1.101
    20  10.0.0.0/24
object-group  ip port  WEB
    10 eq  80
    20  eq 443
    30 range 8000  8999
ip access-list  L3Port
    10 permit  tcp  addrgroup SERVERS  portgroup  WEB  any
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 1)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 80, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 7999, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "10.0.0.37".ipv4address!, destinationIp: "11.0.0.2".ipv4address!, sourcePort: 8000, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
    }

    func testNxosSiemhermans() {
        let sample = """
IP access list ACL_NAME
  10 remark FIRST_REMARK
  20 permit ospf any any
  30 permit udp 10.0.0.0/22 range 5000 10000 host 1.1.1.1 range 1023 1025
  40 permit tcp host 11.0.0.1 range 5000 10000 14.0.0.0/22 gt 1023 established
  50 permit tcp 12.0.0.0/22 gt 1023 10.0.0.0/8 range 6620 6629 established
  60 remark SECOND_REMARK
  70 permit tcp 160.0.0.0/22 gt 1023 10.254.128.0/24 eq 9389
"""
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.accessControlEntries.count == 5)
        
        let socket1 = Socket(ipProtocol: 17, sourceIp: "10.0.3.33".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 10000, destinationPort: 1023, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.0.3.33".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 10000, destinationPort: 1023, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)

        let socket3 = Socket(ipProtocol: 6, sourceIp: "11.0.0.1".ipv4address!, destinationIp: "14.0.3.255".ipv4address!, sourcePort: 10000, destinationPort: 1024, established: true, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)

        let socket4 = Socket(ipProtocol: 6, sourceIp: "11.0.0.1".ipv4address!, destinationIp: "14.0.3.255".ipv4address!, sourcePort: 10000, destinationPort: 1023, established: true, ipVersion: .IPv4)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .deny)

        let socket5 = Socket(ipProtocol: 6, sourceIp: "12.0.1.37".ipv4address!, destinationIp: "10.255.255.255".ipv4address!, sourcePort: 1024, destinationPort: 6629, established: true, ipVersion: .IPv4)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .permit)

        let socket6 = Socket(ipProtocol: 6, sourceIp: "12.0.1.37".ipv4address!, destinationIp: "11.0.0.0".ipv4address!, sourcePort: 1024, destinationPort: 6629, established: true, ipVersion: .IPv4)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6 == .deny)

        let socket7 = Socket(ipProtocol: 6, sourceIp: "160.0.2.191".ipv4address!, destinationIp: "10.254.128.255".ipv4address!, sourcePort: 1024, destinationPort: 9389, established: false, ipVersion: .IPv4)!
        let result7 = acl.analyze(socket: socket7)
        XCTAssert(result7 == .permit)

        let socket8 = Socket(ipProtocol: 6, sourceIp: "160.0.2.191".ipv4address!, destinationIp: "10.254.128.255".ipv4address!, sourcePort: 1024, destinationPort: 9389, established: true, ipVersion: .IPv4)!
        let result8 = acl.analyze(socket: socket8)
        XCTAssert(result8 == .permit)

    }
    
    
    func testNxosInvalid1() {
        let line1 = "40 permit tcp host 11.0.0.1 range 5000 10000"
        let ace = AccessControlEntry(line: line1, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace == nil)
    }
    
    func testNxosInvalid2() {
        let line1 = "40 permit tcp host 11.0.0.1 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace1 != nil)
        
        let line2 = "40 permit tcp host 11.0.0.1 host 2.2.2.2 dscp af11"
        let ace2 = AccessControlEntry(line: line2, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace2 == nil)

        let line3 = "40 permit tcp host 11.0.0.1 host 2.2.2.2 precedence critical"
        let ace3 = AccessControlEntry(line: line3, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace3 == nil)

        let line4 = "40 permit tcp host 11.0.0.1 host 2.2.2.2 log"
        let ace4 = AccessControlEntry(line: line4, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace4 != nil)

        let line5 = "40 permit tcp host 11.0.0.1 host 2.2.2.2 time-range bob"
        let ace5 = AccessControlEntry(line: line5, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace5 == nil)

        let line6 = "40 permit igmp host 11.0.0.1 host 2.2.2.2 dvmrp"
        let ace6 = AccessControlEntry(line: line6, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace6 == nil)

        let line7 = "40 permit tcp host 11.0.0.1 host 2.2.2.2 fin"
        let ace7 = AccessControlEntry(line: line7, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace7 == nil)

        let line8 = "40 permit tcp host 11.0.0.1 host 2.2.2.2 packet-length eq 40"
        let ace8 = AccessControlEntry(line: line8, deviceType: .nxos, linenum: 1, errorDelegate: nil, delegateWindow: nil)
        XCTAssert(ace8 == nil)

    }

    
    func testNxosObjects1() {
        let sample = """
        object-group ip address ipv4-addr-group-13
            host 10.99.32.6
            192.168.7.0/24
            192.168.8.0 0.0.0.255
        object-group ip port NYC-datacenter-ports
            eq 80
            range 30 34
        object-group ip port LA-ports
            neq 77
        object-group ip port TOK-ports
            lt 30
            gt 65500
        ip access-list bob
            15 permit tcp addrgroup ipv4-addr-group-13 10.0.0.0/23 portgroup NYC-datacenter-ports
            17 permit udp 192.168.10.0/24 192.168.11.0/24 portgroup LA-ports
            19 permit tcp 192.168.12.0/24 192.168.13.0/24 portgroup TOK-ports established
        """
        
        let acl = AccessList(sourceText: sample, deviceType: .nxos, delegate: nil, delegateWindow: nil)
        
        XCTAssert(acl.accessControlEntries.count == 3)
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupServices.count == 3)
        
        XCTAssert(acl.objectGroupNetworks.first!.value.ipRanges.count == 3)
        
        XCTAssert(acl.objectGroupServices["nyc-datacenter-ports"]!.portRanges.count == 2)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.99.32.6".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "192.168.7.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .permit)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "192.168.8.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .permit)
        
        let socket4 = Socket(ipProtocol: 6, sourceIp: "192.168.8.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 81, established: false, ipVersion: .IPv4)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4 == .deny)

        let socket5 = Socket(ipProtocol: 6, sourceIp: "192.168.8.33".ipv4address!, destinationIp: "10.0.1.33".ipv4address!, sourcePort: 33, destinationPort: 31, established: false, ipVersion: .IPv4)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5 == .permit)

        let socket6 = Socket(ipProtocol: 17, sourceIp: "192.168.10.33".ipv4address!, destinationIp: "192.168.11.194".ipv4address!, sourcePort: 33, destinationPort: 76, established: false, ipVersion: .IPv4)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6 == .permit)

        let socket7 = Socket(ipProtocol: 17, sourceIp: "192.168.10.33".ipv4address!, destinationIp: "192.168.11.194".ipv4address!, sourcePort: 33, destinationPort: 77, established: false, ipVersion: .IPv4)!
        let result7 = acl.analyze(socket: socket7)
        XCTAssert(result7 == .deny)

        let socket8 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 29, established: true, ipVersion: .IPv4)!
        let result8 = acl.analyze(socket: socket8)
        XCTAssert(result8 == .permit)

        let socket9 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 30, established: true, ipVersion: .IPv4)!
        let result9 = acl.analyze(socket: socket9)
        XCTAssert(result9 == .deny)

        let socket10 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 65501, established: true, ipVersion: .IPv4)!
        let result10 = acl.analyze(socket: socket10)
        XCTAssert(result10 == .permit)

        let socket11 = Socket(ipProtocol: 6, sourceIp: "192.168.12.33".ipv4address!, destinationIp: "192.168.13.194".ipv4address!, sourcePort: 33, destinationPort: 65500, established: true, ipVersion: .IPv4)!
        let result11 = acl.analyze(socket: socket11)
        XCTAssert(result11 == .deny)

    }

}

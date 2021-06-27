//
//  Network_Mom_ACL_AnalyzerTests.swift
//  Network Mom ACL AnalyzerTests
//
//  Created by Darrell Root on 6/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import XCTest
@testable import AclAnalyzerKit

class TestIos: XCTestCase, AclDelegate {

    //Faking acl delegate stuff to allow testing
    func report(aclError: AclError) {
        return
    }
    func getObjectGroupNetwork(_ group: String) -> ObjectGroupNetwork? {
        return nil
    }
    func getObjectGroupService(_ group: String) -> ObjectGroupService? {
        return nil
    }
    func getObjectGroupProtocol(_ group: String) -> ObjectGroupProtocol? {
        return nil
    }
    func getHostname(_ hostname: String) -> UInt128? {
        return nil
    }
    func foundName(_ name: String) {
        return
    }
    // end faking acl delegate stuff to allow testing

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testIosExample1() {
        let sample = """
        access-list 102 permit tcp any 10.88.0.0 0.0.255.255 established
        access-list 102 permit tcp any host 10.88.1.2 eq smtp
        access-list 102 permit tcp any any eq domain
        access-list 102 permit udp any any eq domain
        access-list 102 permit icmp any any echo
        access-list 102 permit icmp any any echo-reply
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 6)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: true, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 25, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3.0 == .permit)
        
        let socket4 = Socket(ipProtocol: 6, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 26, established: false, ipVersion: .IPv4)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4.0 == .deny)
        
        let socket5 = Socket(ipProtocol: 17, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 53, established: false, ipVersion: .IPv4)!
        let result5 = acl.analyze(socket: socket5)
        XCTAssert(result5.0 == .permit)
        
        let socket6 = Socket(ipProtocol: 17, sourceIp: "2.2.2.2".ipv4address!, destinationIp: "10.88.1.2".ipv4address!, sourcePort: 33, destinationPort: 54, established: false, ipVersion: .IPv4)!
        let result6 = acl.analyze(socket: socket6)
        XCTAssert(result6.0 == .deny)
    }

    func testExample() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.2 0.0.0.1", deviceType: .ios, linenum: 1, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        guard let sourceip = "1.1.1.1".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.sourceIp[0].minIp == sourceip)
    }
    
    func testDontCareHostsThree() {
        let three: UInt = 3 // 0.0.0.3
        let dontCareHosts = three.dontCareHosts
        XCTAssert(dontCareHosts == 4)
    }
    
    func testDontCareHostsZero() {
        let zero: UInt = 0 // 0.0.0.0
        let dontCareHosts = zero.dontCareHosts
        XCTAssert(dontCareHosts == 1)
    }

    func testNetmaskZero() {
        let zero: UInt = 0
        let netmaskHosts = zero.netmaskHosts
        XCTAssert(netmaskHosts == 4294967296)
    }
    
    func testNetmaskThirty() {
        let slashThirty: UInt = 4294967292
        let netmaskHosts = slashThirty.netmaskHosts
        XCTAssert(netmaskHosts == 4)
    }
    
    func testBitBoundarySource() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp 3.7.4.18 0.0.0.3 2.2.2.3 0.0.0.1", deviceType: .ios, linenum: 2, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        guard let sourceip = "3.7.4.16".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.sourceIp[0].minIp == sourceip)
    }

    func testEstablished() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2 established", deviceType: .ios, linenum: 4, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == true)
    }
    func testEstablishedMustBeTcp() {
        let ace = AccessControlEntry(line: "permit ip any any established", deviceType: .ios, linenum: 4, aclDelegate: self)
        XCTAssert(ace == nil)
    }
    func testEstablishedCannotBeUdp() {
        let ace = AccessControlEntry(line: "permit udp any any established", deviceType: .ios, linenum: 4, aclDelegate: self)
        XCTAssert(ace == nil)
    }
    func testCmdForMatt() {
        let line1 = "access-list 101 permit tcp 1.2.3.192 0.0.0.63 eq cmd 10.0.0.0 0.255.255.255"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace1 != nil)
    }
    
    func testMultipleSpacesForMatt() {
        let line1 = "access-list 101  permit  tcp  1.2.3.192 0.0.0.63 eq cmd 10.0.0.0 0.255.255.255"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace1 != nil)
    }

    func testIosProtocolNumbered1() {
        let line1 = "access-list 101 permit 6 131.252.209.18 0.0.0.0 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace1 != nil)
    }
    
    func testIosProtocolNumbered2() {
        let line1 = "access-list 101 permit 0 131.252.209.18 0.0.0.0 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace1 == nil)
    }

    func testIosProtocolNumbered3() {
        let line1 = "access-list 101 permit 256 131.252.209.18 0.0.0.0 host 2.2.2.2"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace1 == nil)
    }

    func testIosProtocol3() {
        let sample = """
ip access-list 101 extended
permit ip host 10.4.4.2 any
permit ip host 10.0.0.44 any
permit ip host 10.0.0.1 any
permit ip host 10.0.0.2 any
"""
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        let socket1 = Socket(ipProtocol: 3, sourceIp: "10.4.4.2".ipv4address!, destinationIp: "100.1.1.1".ipv4address!, sourcePort: nil, destinationPort: nil, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .permit)
        
        let socket2 = Socket(ipProtocol: 3, sourceIp: "10.4.4.3".ipv4address!, destinationIp: "100.1.1.1".ipv4address!, sourcePort: nil, destinationPort: nil, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
    }

    func testIosLog() {
        let line1 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1 log"
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace1 != nil)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result1 = ace1?.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let line2 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1 log-input"
        let ace2 = AccessControlEntry(line: line2, deviceType: .ios, linenum: 2, aclDelegate: self)
        XCTAssert(ace2 != nil)
        let result2 = ace2?.analyze(socket: socket1)
        XCTAssert(result2 == .permit)
        let line3 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1 dfwefwef"
        let ace3 = AccessControlEntry(line: line3, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace3 == nil)
        
    }
    func testIosSlash0() {
        let line1 = "access-list 1 permit ip 0.0.0.0 255.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "147.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .permit)
    }

    func testIosSlash1() {
        let line1 = "access-list 1 permit ip 0.0.0.0 127.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "127.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "128.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash2() {
        let line1 = "access-list 1 permit ip 0.0.0.0 63.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "63.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "64.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash3() {
        let line1 = "access-list 1 permit ip 0.0.0.0 31.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "31.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "32.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash4() {
        let line1 = "access-list 1 permit ip 0.0.0.0 15.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "15.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "16.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash5() {
        let line1 = "access-list 1 permit ip 0.0.0.0 7.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "7.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "8.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash6() {
        let line1 = "access-list 1 permit ip 0.0.0.0 3.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "4.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash7() {
        let line1 = "access-list 1 permit ip 0.0.0.0 1.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "1.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "2.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash8() {
        let line1 = "access-list 1 permit ip 0.0.0.0 0.255.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "0.255.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "1.0.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash9() {
        let line1 = "access-list 1 permit ip 3.0.0.0 0.127.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.127.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash10() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.63.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.191.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.192.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash11() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.31.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.159.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.160.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash12() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.15.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.143.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.144.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash13() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.7.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.135.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.136.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash14() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.3.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.131.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.132.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash15() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.1.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.129.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.130.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash16() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.0.255.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.255.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.129.0.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash17() {
        let line1 = "access-list 1 permit ip 3.128.0.0 0.0.127.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.127.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.128.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash18() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.63.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.127.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.128.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash19() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.31.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.95.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.96.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash20() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.15.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.79.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.80.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash21() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.7.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.71.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.72.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash22() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.3.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.67.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.68.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash23() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.1.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.65.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.66.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash24() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.0.255 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.255".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.65.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash25() {
        let line1 = "access-list 1 permit ip 3.128.64.0 0.0.0.127 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.127".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.128".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash26() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.63 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.127".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.128".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash27() {
        let line1 = "access-list 1 permit ip 0.0.0.64 0.0.0.31 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "0.0.0.95".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "0.0.0.96".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash28() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.15 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.79".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.80".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash29() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.7 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.71".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.72".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash30() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.3 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.67".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.68".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosSlash31() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.1 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.65".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.66".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }
    
    func testIosSlash32() {
        let line1 = "access-list 1 permit ip 3.128.64.64 0.0.0.0 host 1.1.1.1"
        let socket11 = Socket(ipProtocol: 6, sourceIp: "3.128.64.64".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let ace1 = AccessControlEntry(line: line1, deviceType: .ios, linenum: 1, aclDelegate: self)!
        let result11 = ace1.analyze(socket: socket11)
        XCTAssert(result11 == .permit)
        let socket12 = Socket(ipProtocol: 6, sourceIp: "3.128.64.65".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4)!
        let result12 = ace1.analyze(socket: socket12)
        XCTAssert(result12 == .neither)
    }

    func testIosNe1() {
        let line = "access-list 101 permit tcp host 1.1.1.1 any neq www"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 1, aclDelegate: self)
        
        let socket1 = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 40, established: false, ipVersion: .IPv4)!
        XCTAssert(ace != nil)
        let result1 = ace?.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "2.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
        let result2 = ace?.analyze(socket: socket2)
        XCTAssert(result2 == .neither)
    }
    
    func testIosNeInvalid1() {
        let line = "access-list 101 permit tcp host 1.1.1.1 any ne ssh"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 1, aclDelegate: self)
        XCTAssert(ace == nil)
    }

    func testIosSequence() {
        let sample = """
        10 permit tcp host 1.1.1.1 host 1.1.1.2 eq 179
        20 permit tcp host 2.1.1.1 eq 179 host 2.2.2.2
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "1.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 179, established: false, ipVersion: .IPv4) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result.0 == .permit)

        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "1.1.1.0".ipv4address!, destinationIp: "1.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 179, established: false, ipVersion: .IPv4) else {
            XCTAssert(false)
            return
        }
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)

    }
    func testDummies1() {
        let sample = """
        access-list 101 remark This ACL is to control the outbound router traffic.
        access-list 101 permit tcp 192.168.8.0 0.0.0.255 any eq 80
        access-list 101 permit tcp 192.168.8.0 0.0.0.255 any eq 443
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        guard let socket = Socket(ipProtocol: 6, sourceIp: "192.168.8.41".ipv4address!, destinationIp: "212.221.4.5".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4) else {
            XCTAssert(false)
            return
        }
        let result = acl.analyze(socket: socket)
        XCTAssert(result.0 == .permit)
        
        guard let socket2 = Socket(ipProtocol: 6, sourceIp: "192.168.3.41".ipv4address!, destinationIp: "212.221.4.5".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4) else {
            XCTAssert(false)
            return
        }
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
    }
    func testAnalyzeEstablished1() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp any any established", deviceType: .ios, linenum: 3, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        guard let socket = Socket(ipProtocol: 6, sourceIp: 3, destinationIp: 5, sourcePort: 33, destinationPort: 44, established: true, ipVersion: .IPv4) else {
            XCTAssert(false)
            return
        }
        let result = ace.analyze(socket: socket)
        XCTAssert(result == .permit)
    }
    func testAnalyzeEstablished2() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp any any established", deviceType: .ios, linenum: 3, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        guard let socket = Socket(ipProtocol: 6, sourceIp: 3, destinationIp: 5, sourcePort: 33, destinationPort: 44, established: false, ipVersion: .IPv4) else {
            XCTAssert(false)
            return
        }
        let result = ace.analyze(socket: socket)
        XCTAssert(result == .neither)
    }

    
    func testNotEstablished() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 host 2.2.2.2", deviceType: .ios, linenum: 4, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.established == false)
    }

    func testBitBoundaryDest() {
        guard let ace = AccessControlEntry(line: "access-list 101 permit tcp host 1.1.1.1 2.2.2.3 0.0.0.1", deviceType: .ios, linenum: 3, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        guard let destip = "2.2.2.2".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destIp[0].minIp == destip)
    }

    func testInvalidProtocolDestPort() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 0.0.0.255 2.2.2.0 0.0.0.255 eq 80", deviceType: .ios, linenum: 5, aclDelegate: self)
        XCTAssert(ace == nil)
    }
    
    func testInvalidNetmaskIos() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 255.255.255.0 2.2.2.0 255.255.255.0", deviceType: .ios, linenum: 5, aclDelegate: self)
        XCTAssert(ace == nil)
    }
    
    func testInvalidProtocolSourcePort() {
        let ace = AccessControlEntry(line: "permit ip 1.1.1.0 0.0.0.255 eq 80 2.2.2.128 0.0.0.63", deviceType: .ios, linenum: 5, aclDelegate: self)
        XCTAssert(ace == nil)
    }
    
    func testUdpNamedPort() {
        let ace = AccessControlEntry(line: "permit udp 1.1.1.0 0.0.0.255 eq snmp 2.2.2.128 0.0.0.63 eq ntp", deviceType: .ios, linenum: 5, aclDelegate: self)
        XCTAssert(ace?.sourcePort[0].minPort == 161)
        XCTAssert(ace?.destPort[0].maxPort == 123)
    }

    func testTcpNamedPort() {
        let ace = AccessControlEntry(line: "permit tcp 1.1.1.0 0.0.0.255 eq domain 2.2.2.128 0.0.0.63 eq www", deviceType: .ios, linenum: 5, aclDelegate: self)
        XCTAssert(ace?.sourcePort[0].maxPort == 53)
        XCTAssert(ace?.destPort[0].minPort == 80)
    }
    func testIcmpName() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 timestamp-reply", deviceType: .ios, linenum: 6, aclDelegate: self)
        XCTAssert(ace?.ipProtocols.first == 1)
    }
    func testIcmpNumber() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 14", deviceType: .ios, linenum: 6, aclDelegate: self)
        XCTAssert(ace?.ipProtocols.first == 1)
        XCTAssert(ace?.icmpMessages.first!.type == 14)
    }
    func testIcmpInvalidName() {
        let ace = AccessControlEntry(line: "access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1 timestamp-bogus", deviceType: .ios, linenum: 6, aclDelegate: self)
        XCTAssert(ace == nil)
    }
    func testIosXrLine() {
        let line = "permit tcp 192.168.36.0 0.0.0.255 any eq 80"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
        XCTAssert(ace?.destPort[0].minPort == 80)
        guard let sourceip = "192.168.36.0".ipv4address else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace?.sourceIp[0].minIp == sourceip)
    }
    
    func testSyslog() {
        let line = "permit udp 192.168.36.0 0.0.0.255 any eq syslog"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
        XCTAssert(ace?.destPort[0].minPort == 514)
    }
    func testRandom1() {
        let line = "permit 17 2.203.38.192 0.0.0.63 lt 9453 242.96.9.128 0.0.0.127 eq 847  log"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
        let socket1 = Socket(ipProtocol: 17, sourceIp: "2.203.38.192".ipv4address!, destinationIp: "242.96.9.128".ipv4address!, sourcePort: 9452, destinationPort: 847, established: false, ipVersion: .IPv4)!
        let result = ace!.analyze(socket: socket1)
        XCTAssert(result == .permit)
    }

    func testDestRange() {
        let line = "permit tcp 157.240.0.0 0.0.31.255 lt 13410 64.0.0.0 15.255.255.255 range 8461 33918  log"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
        XCTAssert(ace != nil)
    }

/*    func testIosObject1() {
        let sample = """
object-group network my_network_object_group
host 209.165.200.237
host 209.165.200.238
range 209.165.200.239 209.165.200.240
209.165.200.241 255.255.255.224
permit tcp object-group my_network_object_group host 1.1.1.1 eq 80
"""
        let acl = AccessList(sourceText: sample, deviceType: .ios, delegate: nil, delegateWindow: nil)
        XCTAssert(acl.objectGroupNetworks.count == 1)
        XCTAssert(acl.objectGroupNetworks.first!.value.ipRanges.count == 4)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1 == .permit)
        let socket2 = Socket(ipProtocol: 6, sourceIp: "209.165.200.200".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2 == .deny)
        let socket3 = Socket(ipProtocol: 6, sourceIp: "209.165.201.0".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 33, destinationPort: 80, established: false)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3 == .deny)

    }*/
    
    func testIosLog2() {
        let sample = """
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
    }
    
    func testIosLogInput() {
        let sample = """
        access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log-input
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
        
    }

    
    func testIsakmp() {
        let line = "permit udp 192.168.36.0 0.0.0.255 any eq isakmp"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
        XCTAssert(ace?.destPort[0].minPort == 500)
    }

    func testNon500isakmp() {
        let line = "permit udp 192.168.36.0 0.0.0.255 any eq non500-isakmp"
        let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
        XCTAssert(ace?.destPort[0].minPort == 4500)
    }

    func testEsp() {
    let line = "permit esp 192.168.36.0 0.0.0.255 host 1.1.1.1 "
    let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 7, aclDelegate: self)
    XCTAssert(ace?.ipProtocols.first == 50)
    }


    
    
    
    func testIosMultiNames() {
        let sample = """
        access-list 102 permit icmp host 10.1.1.1 host 172.16.1.1
        access-list 101 permit icmp host 10.1.1.1 host 172.16.1.1
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.aclNames.count == 2)
    }

    func testIosName() {
        let sample = """
        ip access-list extended blockacl
        deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21
        deny tcp any 172.16.50.0 0.0.0.255 eq 23
        permit ip any any
        """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.count == 3)
        XCTAssert(acl.aclNames.contains("blockacl"))
        
    }
    func testIos() {
        let line = "access-list 110 deny tcp 172.16.40.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 21"
        guard let ace = AccessControlEntry(line: line, deviceType: .ios, linenum: 8, aclDelegate: self) else {
            XCTAssert(false)
            return
        }
        XCTAssert(ace.destPort[0].minPort == 21)
        XCTAssert(ace.ipProtocols.first == 6)
        XCTAssert(ace.aclAction == .deny)
    }
    
    
    func testIosxeLog1() {
        let sample = """
    access-list 101 permit tcp host 10.1.1.1 host 10.1.1.2 log
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "10.1.1.1".ipv4address!, destinationIp: "10.2.2.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
    }
    
    func testIosxe1() {
        let sample = """
    ip access-list extended telnetting
     remark Do not allow host1 subnet to telnet out
     permit tcp host 172.16.2.88 any eq telnet
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 1)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "172.16.2.88".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .permit)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "172.16.2.88".ipv4address!, destinationIp: "10.1.1.2".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .deny)
    }
    func testIosXe2() {
        let sample = """
    ip access-list extended acl1
    deny ip 172.18.0.0 0.0.255.255 host 172.16.40.10 log
    permit tcp any any
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        let socket1 = Socket(ipProtocol: 6, sourceIp: "172.18.3.3".ipv4address!, destinationIp: "172.16.40.10".ipv4address!, sourcePort: 33, destinationPort: 21, established: false, ipVersion: .IPv4)!
        let result1 = acl.analyze(socket: socket1)
        XCTAssert(result1.0 == .deny)
        
        let socket2 = Socket(ipProtocol: 6, sourceIp: "172.18.3.3".ipv4address!, destinationIp: "172.16.40.11".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result2 = acl.analyze(socket: socket2)
        XCTAssert(result2.0 == .permit)
        
        let socket3 = Socket(ipProtocol: 6, sourceIp: "172.17.3.3".ipv4address!, destinationIp: "172.16.40.10".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result3 = acl.analyze(socket: socket3)
        XCTAssert(result3.0 == .permit)
        
        let socket4 = Socket(ipProtocol: 17, sourceIp: "172.17.3.3".ipv4address!, destinationIp: "172.16.40.10".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
        let result4 = acl.analyze(socket: socket4)
        XCTAssert(result4.0 == .deny)
    }
    func testIosNumbered1() {
        let sample = """
    access-list 107 remark allow Telnet packets from any source to network 172.69.0.0 (headquarters)
    access-list 107 permit tcp any 172.69.0.0 0.0.255.255 eq telnet
    access-list 107 remark deny all other TCP packets
    access-list 107 deny tcp any any
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "172.69.3.3".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "172.69.3.3".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "172.68.3.3".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
    }
    func testIosXe3() {
        let sample = """
    ip access-list extended marketing-group
     permit tcp any 172.26.0.0 0.0.255.255 eq telnet
     deny tcp any any
     permit icmp any any
     permit udp any 172.26.0.0 0.0.255.255 lt 1024
     deny ip any any
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 5)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "14.3.3.3".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 1024, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
    }
    func testIosXe4() {
        let sample = """
    ip access-list extended telnetting
     remark Do not allow user1 subnet to telnet out
     deny tcp 172.20.0.0 0.0.255.255 any eq telnet
     remark Allow Top subnet to telnet out
     permit tcp 172.33.0.0 0.0.255.255 any eq telnet
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 22, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.20.255.255".ipv4address!, destinationIp: "172.26.254.254".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
    }
    func testIosXe5() {
        let sample = """
    ip access-list extended acl1
     permit tcp any 172.28.0.0 0.0.255.255 gt 1023
     permit tcp any host 172.28.1.2 eq 25
     permit icmp any 172.28.0.0 255.255.255.255
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 3)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.255.255".ipv4address!, sourcePort: 33, destinationPort: 1024, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.255.255".ipv4address!, sourcePort: 33, destinationPort: 1023, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        
        do {
            let socket = Socket(ipProtocol: 17, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.255.255".ipv4address!, sourcePort: 33, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.1.2".ipv4address!, sourcePort: 33, destinationPort: 25, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.28.1.2".ipv4address!, sourcePort: 33, destinationPort: 26, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
    }
    func testIosXe6() {
        let sample = """
    access-list 102 permit tcp any 172.18.0.0 0.0.255.255 established
    access-list 102 permit tcp any host 172.18.1.2 eq 25
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 25, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.18.1.3".ipv4address!, sourcePort: 33, destinationPort: 25, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.33.255.255".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 26, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
    }
    func testIosXe7() {
        let sample = """
    ip access-list extended no-web
     remark Do not allow w1 to browse the web
     deny tcp host 172.20.3.85 any eq www
     remark Do not allow w2 to browse the web
     deny tcp host 172.20.3.13 any eq www
     remark Allow others on our network to browse the web
     permit tcp 172.20.0.0 0.0.255.255 any eq www
    """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 3)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.20.3.85".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "172.20.3.86".ipv4address!, destinationIp: "172.18.1.2".ipv4address!, sourcePort: 33, destinationPort: 80, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
    }
    
    
    /*    func testIosXeObject1() {
     let sample = """
     object-group my-nested-object-group
     host 1.1.1.1
     object-group network my-network-object-group
     description test engineers
     host 209.165.200.237
     209.165.200.241 255.255.255.224
     group-object my-nested-object-group
     object-group my-nested-service-object-group
     tcp source eq 30
     tcp eq 31
     tcp source eq 32 eq 33
     object-group service my-service-object-group
     description test engineers
     ahp
     tcp-udp range 2000 2005
     icmp conversion-error
     group-object my-nested-service-object-group
     ip access-list extended nomarketing
     remark protect server by denying access from the Marketing network
     permit object-group my-service-object-group object-group my-network-object-group host 1.1.1.1 log
     """
     let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
     XCTAssert(acl.accessControlEntries.count == 3)
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.245".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 80, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 43, destinationPort: 31, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 32, destinationPort: 33, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     }*/
    /*    func testIosXeObject2() {
     let sample = """
     object-group network my-network-object-group
     description test engineers
     host 209.165.200.237
     host 209.165.200.238
     209.165.200.241 255.255.255.224
     object-group network my-company-network
     host 209.165.200.242
     209.165.200.225 255.255.255.224
     group-object my-network-object-group
     object-group service my-service-object-group
     icmp echo
     tcp smtp
     tcp telnet
     tcp source range 50 65535 telnet
     tcp source 2000 ftp
     udp domain
     tcp-udp range 2000 2005
     group-object my-nested-object-group
     ip access-list extended my-ogacl-policy
     permit object-group my-service-object-group object-group my-network-object-group any
     deny tcp any any
     """
     let acl = AccessList(sourceText: sample, deviceType: .iosxe, delegate: nil, delegateWindow: nil)
     XCTAssert(acl.accessControlEntries.count == 3)
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 25, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.236".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 25, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 26, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     do {
     let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.241".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 50, destinationPort: 23, established: false)!
     let result = acl.analyze(socket: socket)
     XCTAssert(result.0 == .permit)
     }
     }*/
    func testIosXeObject1() {
        let sample = """
 object-group network my-nested-object-group
    host 1.1.1.1
 object-group network my-network-object-group
    description test engineers
    host 209.165.200.237
    209.165.200.241 255.255.255.224
    group-object my-nested-object-group
 ip access-list extended nomarketing
    remark protect server by denying access from the Marketing network
    permit tcp object-group my-network-object-group range 10 20 host 1.1.1.1 eq 30 log
 """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 1)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.245".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 20, destinationPort: 30, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.2".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 10, destinationPort: 30, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "1.1.1.1".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 9, destinationPort: 30, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        
        
    }
    func testIosXeObject2() {
        let sample = """
 object-group network my-network-object-group
 description test engineers
    host 209.165.200.237
    host 209.165.200.238
    209.165.200.241 255.255.255.224
 object-group network my-company-network
    host 209.165.200.242
    209.165.200.225 255.255.255.224
    group-object my-network-object-group
 ip access-list extended my-ogacl-policy
 permit tcp object-group my-network-object-group any
 deny tcp any any
 """
        let acl = AccessList(sourceText: sample, deviceType: .ios)
        XCTAssert(acl.accessControlEntries.count == 2)
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 25, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.236".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 25, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.237".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 30, destinationPort: 26, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.241".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 50, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.223".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 50, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .deny)
        }
        do {
            let socket = Socket(ipProtocol: 6, sourceIp: "209.165.200.224".ipv4address!, destinationIp: "1.1.1.1".ipv4address!, sourcePort: 50, destinationPort: 23, established: false, ipVersion: .IPv4)!
            let result = acl.analyze(socket: socket)
            XCTAssert(result.0 == .permit)
        }
    }


}

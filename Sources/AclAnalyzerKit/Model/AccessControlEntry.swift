//
//  AccessControlEntry.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

struct AccessControlEntry {
    
    static let ANYIPV6RANGE: IpRange = IpRange(minIp: 0, maxIp: UInt128.max, ipVersion: .IPv6)

    var aclAction: AclAction = .neither  // neither means not initialized
    //var ipVersion: IpVersion
    var listName: String?
    var ipProtocols: [UInt] = []  // 0 means ip
    var sourceIp: [IpRange] = []
    var sourcePort: [PortRange] = []  //empty list means no port restriction
    var destIp: [IpRange] = []
    var destPort: [PortRange] = []  // empty means no port restriction
    var established: Bool = false
    var line: String
    var linenum: Int
    var icmpMessages: [IcmpMessage] = []
    var sequence: UInt?  // If a sequence number exists in the line
    
    var counter = false // set to true first time we counter, second counter triggers error
    var log = false  // set to true first time we log, second log triggers error
    
    let MAXIP = UInt(UInt32.max)
    let MAXPORT = UInt(UInt16.max)
    let ANYIPRANGE = IpRange(minIp: 0, maxIp: UInt(UInt32.max), ipVersion: .IPv4)
    let ANYPORTRANGE = PortRange(minPort: 0, maxPort: UInt(UInt16.max))!
    
    func findAction(word: String) -> AclAction? {
        switch word {
        case "deny":
            return .deny
        case "permit":
            return .permit
        default:
            return nil
        }
    }
    
    enum IosLinePositionV6 {
        case beginning
        case action
        case ipProtocol
        case sourceIp
        case sourceIpHost
        case sourcePortOperator
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destPortOperator
        case firstDestPort
        case lastDestPort
        case flags
        case sequence
        case comment // comment spotted, can ignore everything from here on
        case end // end without comment, still need to check syntax
    }

    enum AsaLinePosition: String {
        case beginning
        case accessList
        case listName
        case extended
        case action
        case ipProtocol
        case protocolObjectGroup
        case sourceIp
        case sourceObjectGroup
        case sourceIpHost
        case sourceMask
        case sourcePortOperator
        case sourcePortObjectGroup  // could be object group for dest network or source port
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destObjectGroup
        case destMask
        case destPortOperator
        case firstDestPort
        case lastDestPort
        case destObjectService
        case icmpType
        case comment
        case log
        case logInterval
        case end
    }
    
    enum NxLinePosition {
        case beginning
        case sequence
        case action
        case ipProtocol
        case sourceIp
        case sourceIpHost
        case sourceAddrgroup
        case sourcePortOperator
        case sourcePortgroup
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destAddrgroup
        case destPortOperator
        case destPortgroup
        case firstDestPort
        case lastDestPort
        case end  // includes capture session 3
    }
    
    enum AristaLinePosition {
        case beginning
        case sequence
        case action
        case ipProtocol
        case sourceIp
        case sourceIpHost
        case sourcePortOperator
        case equalSourcePortList
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destPortOperator
        case equalDestPortList
        case firstDestPort
        case lastDestPort
        case end
    }
    
    enum IosLinePosition {
        case beginning
        case sequence
        case accessList
        case listName
        case action
        case ipProtocol
        case sourceIp
        case sourceIpHost
        case sourceMask
        case sourceNetgroup
        case sourcePortOperator
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destMask
        case destNetgroup
        case destPortOperator
        case firstDestPort
        case lastDestPort
        case flags
        case icmpType
        case comment // comment spotted, can ignore everything from here on
        case end // end without comment, still need to check syntax
    }

    enum IosXrLinePosition {
        case beginning
        case sequence
        case action
        case ipProtocol
        case sourceIp
        case sourceIpHost
        case sourceIpOnly
        case sourceIpHostOnly
        case sourceMask
        case sourceNetgroup
        case sourcePortgroup
        case sourcePortOperator
        case firstSourcePort
        case lastSourcePort
        case destIp
        case destIpHost
        case destMask
        case destNetgroup
        case destPortgroup
        case destPortOperator
        case firstDestPort
        case lastDestPort
        case flags
        case icmpType
        case counter
        case comment // comment spotted, can ignore everything from here on
        case end // end without comment, still need to check syntax
    
    }
    
    public func isDuplicate(of topAce: AccessControlEntry) -> Bool {
        for ipProtocol in self.ipProtocols {
            guard topAce.ipProtocols.contains(0) || topAce.ipProtocols.contains(ipProtocol) else {
                return false
            }
        }
        for selfIpRange in self.sourceIp {
            var thisRangeOk = false
            for topIpRange in topAce.sourceIp {
                if selfIpRange.minIp >= topIpRange.minIp && selfIpRange.maxIp <= topIpRange.maxIp && selfIpRange.ipVersion == topIpRange.ipVersion {
                    thisRangeOk = true
                }
            }
            if thisRangeOk == false {
                return false
            }
        }
        
        for selfIpRange in self.destIp {
            var thisRangeOk = false
            for topIpRange in topAce.destIp {
                if selfIpRange.minIp >= topIpRange.minIp && selfIpRange.maxIp <= topIpRange.maxIp && selfIpRange.ipVersion == topIpRange.ipVersion {
                    thisRangeOk = true
                }
            }
            if thisRangeOk == false {
                return false
            }
        }
        
        if (self.ipProtocols.contains(6) || self.ipProtocols.contains(17)) && (topAce.ipProtocols.contains(6) || topAce.ipProtocols.contains(17)) {
            if self.sourcePort.count == 0 || topAce.sourcePort.count == 0 {
                debugPrint("self.sourcePort.count == 0 ERROR")
            }
            for selfPortRange in self.sourcePort {
                var thisPortOk = false

                for topPortRange in topAce.sourcePort {
                    if selfPortRange.minPort >= topPortRange.minPort && selfPortRange.maxPort <= topPortRange.maxPort {
                        thisPortOk = true
                    }
                }
                if thisPortOk == false {
                    return false
                }
            }// for selfPortRange in sourcePort
            
            if self.destPort.count == 0 || topAce.destPort.count == 0 {
                debugPrint("self.destPort.count == 0 ERROR")
            }
            for selfPortRange in self.destPort {
                var thisPortOk = false
                
                for topPortRange in topAce.destPort {
                    if selfPortRange.minPort >= topPortRange.minPort && selfPortRange.maxPort <= topPortRange.maxPort {
                        thisPortOk = true
                    }
                }
                if thisPortOk == false {
                    return false
                }
            }// for selfPortRange in destPort

        }
        
        // if protocol tcp and if topace only covers established, we must be established
        if self.ipProtocols.contains(6) {
            if topAce.established == true {
                guard self.established == true else {
                    return false
                }
            }
        }
        
        // we do not test for ICMP at this time
        if self.ipProtocols.contains(1) {
            return false
        }
        
        return true
    }
    //MARK: GLOBAL INIT
    
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?) {
        
        switch deviceType {
        case .ios:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, ios: true)
        case .iosv6:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, iosv6: true)
        case .asa:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, asa: true)
        case .nxos:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, nxos: true)
        case .nxosv6:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, nxosv6: true)
        case .iosxr:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, iosxr: true)
        case .iosxrv6:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, iosxrv6: true)
        case .arista:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, arista: true)
        case .aristav6:
            self.init(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: aclDelegate, errorDelegate: errorDelegate, delegateWindow: delegateWindow, aristav6: true)

        }
    }
    
    //MARK: IOS IPv6
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, iosv6: Bool) {
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: IosLinePositionV6 = .beginning
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT)
                sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: UInt.MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }
        
        func validateIosV6() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
            
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            for ip in sourceIp {
                guard ip.ipVersion != .IPv4 else {
                    return false
                }
            }
            for ip in destIp {
                guard ip.ipVersion != .IPv4 else {
                    return false
                }
            }

            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(PortRange.ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(PortRange.ANYPORTRANGE)
                }
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(PortRange.ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(PortRange.ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
                if self.established == true { return false }
            default:
                // should not get here
                return false
            }
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }
            
            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            return true
        }//ValidateIos
        
        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }
        wordLoop: for word in words {
            guard let token = IosTokenV6(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any,.host,.portOperator,.log,.established,.name,.addressV6,.cidrV6,.number,.sequence:
                    reportError()
                    return nil
                case .comment:
                    return nil
            }//switch linePosition
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.name,.sequence:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    guard ipProtocol < 256 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portOperator,.comment,.log,.established,.addressV6,.number,.name,.sequence:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                case .cidrV6(let ipV6Range):
                    self.sourceIp = [ipV6Range]
                    linePosition = .sourceIp
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.cidrV6,.number,.name,.sequence:
                    reportError()
                    return nil
                case .addressV6(let address):
                    let ipRangeV6 = IpRange(minIp: address, maxIp: address, ipVersion: .IPv6)
                    self.sourceIp = [ipRangeV6]
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.comment,.log,.established,.addressV6,.number,.name,.sequence:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let sourcePortOperator):
                    tempSourcePortOperator = sourcePortOperator
                    linePosition = .sourcePortOperator
                case .cidrV6(let ipV6Range):
                    self.destIp = [ipV6Range]
                    linePosition = .destIp
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.sequence:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                // line position set in analyzeFirstSourcePort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.sequence:
                    reportError()
                    return nil
                case .number(let port):
                    guard let tempFirstSourcePort = tempFirstSourcePort, port <= UInt.MAXPORT, tempSourcePortOperator == .range, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                case .name(let name):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = name.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = name.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstSourcePort = tempFirstSourcePort, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portOperator,.comment,.log,.established,.addressV6,.number,.name,.sequence:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.cidrV6,.number,.name,.sequence:
                    reportError()
                    return nil
                case .addressV6(let address):
                    let ipRange = IpRange(minIp: address, maxIp: address, ipVersion: .IPv6)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .portOperator(let portOperator):
                    tempDestPortOperator = portOperator
                    linePosition = .destPortOperator
                case .comment:
                    linePosition = .comment
                case .sequence:
                    linePosition = .sequence
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.sequence:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstDestPort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                // line position set in analyzeFirstDestPort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.sequence:
                    reportError()
                    return nil
                case .number(let secondDestPort):
                    guard let tempFirstDestPort = tempFirstDestPort, secondDestPort <= UInt.MAXPORT, tempDestPortOperator == .range, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                case .name(let secondPortString):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = secondPortString.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = secondPortString.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstDestPort = tempFirstDestPort, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .sequence:
                    linePosition = .sequence
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .flags:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .sequence:
                    linePosition = .sequence
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .comment:
                linePosition = .comment
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.sequence,.comment,.established,.addressV6,.cidrV6,.name,.log:
                    reportError()
                    return nil
                case .number(let sequenceNumber):
                    guard self.sequence == nil else {
                        reportError()
                        return nil
                    }
                    self.sequence = sequenceNumber
                    linePosition = .end
                }
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.portOperator,.established,.number,.name,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .sequence:
                    linePosition = .sequence
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            }
        }//wordLoop for word in words
        if validateIosV6() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }// init iosv6

    //MARK: Arista IPV4 INIT
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, arista: Bool) {
        
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: AristaLinePosition = .beginning
        var tempSourcePortList: [UInt] = [] // used for eq and neq for arista only
        var tempDestPortList: [UInt] = []  // used for eq and neq for arista only
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }

        func validateArista() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
            
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            
            // arista only
            if tempSourcePortList.count > 10 { return false }
            if tempDestPortList.count > 10 { return false }
            
            if let tempSourcePortOperator = tempSourcePortOperator, tempSourcePortOperator == .ne {
                if tempSourcePortList.count < 1 { return false }
                tempSourcePortList.append(65536)
                var lastPortPlus: UInt = 0
                for port in tempSourcePortList.sorted() {
                    if port > lastPortPlus {
                        if let portRange = PortRange(minPort: lastPortPlus, maxPort: port - 1) {
                            self.sourcePort.append(portRange)
                        }
                    }
                    lastPortPlus = port + 1
                }
            }
            
            if let tempDestPortOperator = tempDestPortOperator, tempDestPortOperator == .ne {
                if tempDestPortList.count < 1 { return false }
                tempDestPortList.append(65536)
                var lastPortPlus: UInt = 0
                for port in tempDestPortList.sorted() {
                    if port > lastPortPlus {
                        if let portRange = PortRange(minPort: lastPortPlus, maxPort: port - 1) {
                            self.destPort.append(portRange)
                        }
                    }
                    lastPortPlus = port + 1
                }
            }

            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                break
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
            default:
                // should not get here
                return false
            }
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }

            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            return true
        }
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                self.sourcePort.append(portRange)
                tempSourcePortList.append(firstPort)
                linePosition = .equalSourcePortList
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0 , let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                tempSourcePortList.append(firstPort)
                linePosition = .equalSourcePortList
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                self.destPort.append(portRange)
                linePosition = .equalDestPortList
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                tempDestPortList.append(firstPort)
                linePosition = .equalDestPortList
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }

        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = AristaAclToken(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .number(let sequence): // acl initializer checks for sequence order
                    self.sequence = sequence
                    linePosition = .sequence
                case .ipProtocol,.any, .host, .portOperator, .fourOctet,.established,.log, .cidr, .name:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any, .host, .portOperator, .established,.cidr, .name, .log, .number, .fourOctet:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .any, .host, .portOperator, .comment, .established, .cidr,.name, .log, .fourOctet:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.portOperator,.comment,.established,.number,.log,.name, .fourOctet:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)]
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                case .cidr(let ipRange):
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.comment,.established,.number,.name, .log, .fourOctet:
                    reportError()
                    return nil
                case .any:  //destination any
                    self.destIp = [IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let portOperator):  // source port
                    tempSourcePortOperator = portOperator
                    linePosition = .sourcePortOperator
                case .cidr(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.portOperator,.comment,.established,.log, .cidr,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let ipAddress):
                    let ipRange = IpRange(minIp: ipAddress, maxIp: ipAddress, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment,.log, . established, . fourOctet, .cidr:
                    reportError()
                    return nil
                    
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                }
            case .equalSourcePortList:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment,.log, .established, .fourOctet:
                    reportError()
                    return nil
                case .number(let sourcePort):
                    guard analyzeFirstSourcePort(firstPort: sourcePort) else {
                        reportError()
                        return nil
                    }
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .cidr(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment,.log, .established, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .number(let secondSourcePort):
                    
                    guard let firstSourcePort = tempFirstSourcePort, secondSourcePort >= 0, secondSourcePort <= MAXPORT, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let portRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort)  else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [portRange]
                    linePosition = .lastSourcePort
                case .name(let secondPortString):
                    guard let firstSourcePort = tempFirstSourcePort, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondSourcePort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let sourcePortRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [sourcePortRange]
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment, .established, .fourOctet,.log,.number, .name:
                    reportError()
                    return nil
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .cidr(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .name(let possibleIcmpMessage):
                    guard self.ipProtocols.first == 1, let icmpMessage = IcmpMessage(deviceType: deviceType, message: possibleIcmpMessage) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .number(let possibleIcmpType):
                    guard self.ipProtocols.first == 1, possibleIcmpType < 256, let icmpMessage = IcmpMessage(type: possibleIcmpType, code: nil) else {
                        reportError()
                        return nil
                    }
                    // temporarly assume icmp code is 0 and save it.  if we get a code we will rewrite
                    // this only works if one and only one icmp message can come in on a config line
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .portOperator(let destPortOperator):
                    tempDestPortOperator = destPortOperator
                    linePosition = .destPortOperator
                case .comment, .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .portOperator,.comment, .log, .established,.cidr, .number, .name:
                    reportError()
                    return nil
                case .fourOctet(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator,.established, .log, .fourOctet, .cidr, .comment:
                    reportError()
                    return nil
                case .number(let firstPortNumber):
                    
                    guard analyzeFirstDestPort(firstPort: firstPortNumber) else {
                        reportError()
                        return nil
                    }

                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                }
            case .equalDestPortList:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .fourOctet, .any, .host,.cidr:
                    reportError()
                    return nil
                case .number(let destPort):
                    guard analyzeFirstDestPort(firstPort: destPort) else {
                        reportError()
                        return nil
                    }
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .comment:
                    linePosition = .end
                case .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator,.comment, .log, .established, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .number(let lastDestPort):
                    guard lastDestPort >= 0,
                        lastDestPort <= MAXPORT,
                        let firstDestPort = tempFirstDestPort,
                        let destPortOperator = tempDestPortOperator,
                        destPortOperator == .range,
                        let portRange = PortRange(minPort: firstDestPort, maxPort: lastDestPort) else {
                            reportError()
                            return nil
                    }
                self.destPort = [portRange]
                linePosition = .lastDestPort
                case .name(let secondPortString):
                    guard let firstDestPort = tempFirstDestPort, let destPortOperator = tempDestPortOperator, destPortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondDestPort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .arista, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let destPortRange = PortRange(minPort: firstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort = [destPortRange]
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any, .host, .portOperator, .fourOctet,.cidr, .number, .name:
                    reportError()
                    return nil
                case .comment, .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_):
                    break
                case .ipProtocol(_):
                    break
                case .any:
                    break
                case .host:
                    break
                case .portOperator(_):
                    break
                case .comment:
                    break
                case .log:
                    break
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                case .fourOctet(_):
                    break
                case .cidr(_):
                    break
                case .number(_):
                    break
                case .name(_):
                    break
                }
            }
        }
        if validateArista() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }

    //MARK: Arista IPV6 INIT
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, aristav6: Bool) {
        
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: AristaLinePosition = .beginning
        var tempSourcePortList: [UInt] = [] // used for eq and neq for arista only
        var tempDestPortList: [UInt] = []  // used for eq and neq for arista only
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }

        func validateArista() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
            
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            
            // arista only
            if tempSourcePortList.count > 10 { return false }
            if tempDestPortList.count > 10 { return false }
            
            if let tempSourcePortOperator = tempSourcePortOperator, tempSourcePortOperator == .ne {
                if tempSourcePortList.count < 1 { return false }
                tempSourcePortList.append(65536)
                var lastPortPlus: UInt = 0
                for port in tempSourcePortList.sorted() {
                    if port > lastPortPlus {
                        if let portRange = PortRange(minPort: lastPortPlus, maxPort: port - 1) {
                            self.sourcePort.append(portRange)
                        }
                    }
                    lastPortPlus = port + 1
                }
            }
            
            if let tempDestPortOperator = tempDestPortOperator, tempDestPortOperator == .ne {
                if tempDestPortList.count < 1 { return false }
                tempDestPortList.append(65536)
                var lastPortPlus: UInt = 0
                for port in tempDestPortList.sorted() {
                    if port > lastPortPlus {
                        if let portRange = PortRange(minPort: lastPortPlus, maxPort: port - 1) {
                            self.destPort.append(portRange)
                        }
                    }
                    lastPortPlus = port + 1
                }
            }

            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                break
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
            default:
                // should not get here
                return false
            }
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }

            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            return true
        }
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                self.sourcePort.append(portRange)
                tempSourcePortList.append(firstPort)
                linePosition = .equalSourcePortList
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0 , let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                tempSourcePortList.append(firstPort)
                linePosition = .equalSourcePortList
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                self.destPort.append(portRange)
                linePosition = .equalDestPortList
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                tempDestPortList.append(firstPort)
                linePosition = .equalDestPortList
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }

        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = AristaAclTokenV6(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .number(let sequence): // acl initializer checks for sequence order
                    self.sequence = sequence
                    linePosition = .sequence
                case .ipProtocol,.any, .host, .portOperator, .addressV6,.established,.log, .cidrV6, .name:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any, .host, .portOperator, .established,.cidrV6, .name, .log, .number, .addressV6:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .any, .host, .portOperator, .comment, .established, .cidrV6,.name, .log, .addressV6:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.portOperator,.comment,.established,.number,.log,.name, .addressV6:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv6)]
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                case .cidrV6(let ipRange):
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.comment,.established,.number,.name, .log, .addressV6:
                    reportError()
                    return nil
                case .any:  //destination any
                    self.destIp = [IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv6)]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let portOperator):  // source port
                    tempSourcePortOperator = portOperator
                    linePosition = .sourcePortOperator
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.portOperator,.comment,.established,.log, .cidrV6,.number,.name:
                    reportError()
                    return nil
                case .addressV6(let ipAddress):
                    let ipRange = IpRange(minIp: ipAddress, maxIp: ipAddress, ipVersion: .IPv6)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment,.log, . established, . addressV6, .cidrV6:
                    reportError()
                    return nil
                    
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                }
            case .equalSourcePortList:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment,.log, .established, .addressV6:
                    reportError()
                    return nil
                case .number(let sourcePort):
                    guard analyzeFirstSourcePort(firstPort: sourcePort) else {
                        reportError()
                        return nil
                    }
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv6)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment,.log, .established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .number(let secondSourcePort):
                    
                    guard let firstSourcePort = tempFirstSourcePort, secondSourcePort >= 0, secondSourcePort <= MAXPORT, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let portRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort)  else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [portRange]
                    linePosition = .lastSourcePort
                case .name(let secondPortString):
                    guard let firstSourcePort = tempFirstSourcePort, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondSourcePort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let sourcePortRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [sourcePortRange]
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment, .established, .addressV6,.log,.number, .name:
                    reportError()
                    return nil
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv6)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .name(let possibleIcmpMessage):
                    guard self.ipProtocols.first == 1, let icmpMessage = IcmpMessage(deviceType: deviceType, message: possibleIcmpMessage) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .number(let possibleIcmpType):
                    guard self.ipProtocols.first == 1, possibleIcmpType < 256, let icmpMessage = IcmpMessage(type: possibleIcmpType, code: nil) else {
                        reportError()
                        return nil
                    }
                    // temporarly assume icmp code is 0 and save it.  if we get a code we will rewrite
                    // this only works if one and only one icmp message can come in on a config line
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .portOperator(let destPortOperator):
                    tempDestPortOperator = destPortOperator
                    linePosition = .destPortOperator
                case .comment, .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .portOperator,.comment, .log, .established,.cidrV6, .number, .name:
                    reportError()
                    return nil
                case .addressV6(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv6)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator,.established, .log, .addressV6, .cidrV6, .comment:
                    reportError()
                    return nil
                case .number(let firstPortNumber):
                    
                    guard analyzeFirstDestPort(firstPort: firstPortNumber) else {
                        reportError()
                        return nil
                    }

                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                }
            case .equalDestPortList:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .addressV6, .any, .host,.cidrV6:
                    reportError()
                    return nil
                case .number(let destPort):
                    guard analyzeFirstDestPort(firstPort: destPort) else {
                        reportError()
                        return nil
                    }
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .comment:
                    linePosition = .end
                case .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator,.comment, .log, .established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .number(let lastDestPort):
                    guard lastDestPort >= 0,
                        lastDestPort <= MAXPORT,
                        let firstDestPort = tempFirstDestPort,
                        let destPortOperator = tempDestPortOperator,
                        destPortOperator == .range,
                        let portRange = PortRange(minPort: firstDestPort, maxPort: lastDestPort) else {
                            reportError()
                            return nil
                    }
                self.destPort = [portRange]
                linePosition = .lastDestPort
                case .name(let secondPortString):
                    guard let firstDestPort = tempFirstDestPort, let destPortOperator = tempDestPortOperator, destPortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondDestPort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .aristav6, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let destPortRange = PortRange(minPort: firstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort = [destPortRange]
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any, .host, .portOperator, .addressV6,.cidrV6, .number, .name:
                    reportError()
                    return nil
                case .comment, .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_):
                    break
                case .ipProtocol(_):
                    break
                case .any:
                    break
                case .host:
                    break
                case .portOperator(_):
                    break
                case .comment:
                    break
                case .log:
                    break
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                case .addressV6(_):
                    break
                case .cidrV6(_):
                    break
                case .number(_):
                    break
                case .name(_):
                    break
                }
            }
        }
        if validateArista() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }

    //MARK: NXOS IPV4 INIT
    
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, nxos: Bool) {
        
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: NxLinePosition = .beginning
        
        self.line = line
        self.linenum = linenum
        
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }

        func validateNxos() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
            
            
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                break
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
            default:
                // should not get here
                return false
            }
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }

            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            return true
        }
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0 , let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                self.sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }

        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = NxAclToken(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .number(let sequence): // acl initializer checks for sequence order
                    self.sequence = sequence
                    linePosition = .sequence
                case .ipProtocol,.any, .host, .portOperator, .fourOctet,.established, .addrgroup,.portgroup,.log, .cidr, .name:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any, .host, .portOperator, .established, .addrgroup,.portgroup,.cidr, .name, .log, .number, .fourOctet:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .any, .host, .portOperator, .comment, .established, .cidr, .addrgroup,.portgroup,.name, .log, .fourOctet:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.portOperator,.comment,.established,.number,.log, .portgroup,.name, .fourOctet:
                    reportError()
                    return nil
                case .addrgroup:
                    linePosition = .sourceAddrgroup
                case .any:
                    self.sourceIp = [IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)]
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                case .cidr(let ipRange):
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourceAddrgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.fourOctet,.cidr,.number:
                    reportError()
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup.ipRanges
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.comment,.established,.number,.name, .log, .fourOctet:
                    reportError()
                    return nil
                case .any:  //destination any
                    self.destIp = [IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let portOperator):  // source port
                    tempSourcePortOperator = portOperator
                    linePosition = .sourcePortOperator
                case .cidr(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .addrgroup:
                    linePosition = .destAddrgroup
                case .portgroup:
                    linePosition = .sourcePortgroup
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.portOperator,.comment,.established,.addrgroup,.portgroup,.log, .cidr,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let ipAddress):
                    let ipRange = IpRange(minIp: ipAddress, maxIp: ipAddress, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourcePortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.fourOctet,.cidr,.number:
                    reportError()
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard sourceObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Empty port object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourcePort = sourceObjectGroup.portRanges
                    linePosition = .lastSourcePort
                }
            case .sourcePortOperator:
                
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment, .addrgroup,.portgroup,.log, . established, . fourOctet, .cidr:
                    reportError()
                    return nil
                    
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment, .addrgroup,.portgroup,.log, .established, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .number(let secondSourcePort):
                    guard let firstSourcePort = tempFirstSourcePort, secondSourcePort >= 0, secondSourcePort <= MAXPORT, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let portRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort)  else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [portRange]
                    linePosition = .lastSourcePort
                case .name(let secondPortString):
                    guard let firstSourcePort = tempFirstSourcePort, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondSourcePort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let sourcePortRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [sourcePortRange]
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment, .established, .fourOctet,.log, .portgroup,.number, .name:
                    reportError()
                    return nil
                case .any:
                    let ipRange = IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .addrgroup:
                    linePosition = .destAddrgroup
                case .cidr(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destAddrgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.fourOctet,.cidr,.number:
                    reportError()
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = destObjectGroup.ipRanges
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .fourOctet, .cidr, .number, .addrgroup,.name:
                    reportError()
                    return nil
                case .portOperator(let destPortOperator):
                    tempDestPortOperator = destPortOperator
                    linePosition = .destPortOperator
                case .comment, .log:
                    linePosition = .end
                case .portgroup:
                    linePosition = .destPortgroup
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .portOperator,.comment, .log, .established,.cidr, .number, .addrgroup,.portgroup,.name:
                    reportError()
                    return nil
                case .fourOctet(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .addrgroup,.portgroup,.established, .log, .fourOctet, .cidr, .comment:
                    reportError()
                    return nil
                case .number(let firstPortNumber):
                    
                    guard analyzeFirstDestPort(firstPort: firstPortNumber) else {
                        reportError()
                        return nil
                    }

                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                }
            case .destPortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.fourOctet,.cidr,.number:
                    reportError()
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard destObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Empty port object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destPort = destObjectGroup.portRanges
                    linePosition = .lastDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .addrgroup,.portgroup,.comment, .log, .established, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .number(let lastDestPort):
                    guard lastDestPort >= 0,
                        lastDestPort <= MAXPORT,
                        let firstDestPort = tempFirstDestPort,
                        let destPortOperator = tempDestPortOperator,
                        destPortOperator == .range,
                        let portRange = PortRange(minPort: firstDestPort, maxPort: lastDestPort) else {
                            reportError()
                            return nil
                    }
                self.destPort = [portRange]
                linePosition = .lastDestPort
                case .name(let secondPortString):
                    guard let firstDestPort = tempFirstDestPort, let destPortOperator = tempDestPortOperator, destPortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondDestPort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let destPortRange = PortRange(minPort: firstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort = [destPortRange]
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any, .host, .portOperator, .fourOctet, .addrgroup,.portgroup,.cidr, .number, .name:
                    reportError()
                    return nil
                case .comment, .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .addrgroup:
                    break
                case .portgroup:
                    break
                case .action(_):
                    break
                case .ipProtocol(_):
                    break
                case .any:
                    break
                case .host:
                    break
                case .portOperator(_):
                    break
                case .comment:
                    break
                case .log:
                    break
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                case .fourOctet(_):
                    break
                case .cidr(_):
                    break
                case .number(_):
                    break
                case .name(_):
                    break
                }
            }
        }
        if validateNxos() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }
    

    //MARK: NXOS IPV6 INIT
    
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, nxosv6: Bool) {

        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: NxLinePosition = .beginning
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }

        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }

        func validateNxos() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
            
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                break
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
            default:
                // should not get here
                return false
            }
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }
            
            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            return true
        }

        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0 , let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                self.sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                self.sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }

        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true = success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }

        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }

        wordLoop: for word in words {
            guard let token = NxAclTokenV6(string: word) else {
                reportError()
                return nil
            }

            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .number(let sequence): // acl initializer checks for sequence order
                    self.sequence = sequence
                    linePosition = .sequence
                case .ipProtocol,.any, .host, .portOperator, .addressV6,.established, .addrgroup,.portgroup,.log, .cidrV6, .name:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol,.any, .host, .portOperator, .established, .addrgroup,.portgroup,.cidrV6, .name, .log, .number, .addressV6:
                    reportError()
                    return nil
                case .comment:
                    //no error needed
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .any, .host, .portOperator, .comment, .established, .cidrV6, .addrgroup,.portgroup,.name, .log, .addressV6:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.portOperator,.comment,.established,.number,.log, .portgroup,.name, .addressV6:
                    reportError()
                    return nil
                case .addrgroup:
                    linePosition = .sourceAddrgroup
                case .any:
                    self.sourceIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .sourceIp
                case .host:
                    linePosition = .sourceIpHost
                case .cidrV6(let ipRange):
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourceAddrgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.addressV6,.cidrV6,.number:
                    reportError()
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup.ipRanges
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.comment,.established,.number,.name, .log, .addressV6:
                    reportError()
                    return nil
                case .any:  //destination any
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let portOperator):  // source port
                    tempSourcePortOperator = portOperator
                    linePosition = .sourcePortOperator
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .addrgroup:
                    linePosition = .destAddrgroup
                case .portgroup:
                    linePosition = .sourcePortgroup
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.portOperator,.comment,.established,.addrgroup,.portgroup,.log, .cidrV6,.number,.name:
                    reportError()
                    return nil
                case .addressV6(let ipAddress):
                    let ipRange = IpRange(minIp: ipAddress, maxIp: ipAddress, ipVersion: .IPv6)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceIp
                }
            case .sourcePortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.addressV6,.cidrV6,.number:
                    reportError()
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard sourceObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Empty port object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourcePort = sourceObjectGroup.portRanges
                    linePosition = .lastSourcePort
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment, .addrgroup,.portgroup,.log, . established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .comment, .addrgroup,.portgroup,.log, .established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .number(let secondSourcePort):
                    guard let firstSourcePort = tempFirstSourcePort, secondSourcePort >= 0, secondSourcePort <= MAXPORT, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let portRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort)  else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [portRange]
                    linePosition = .lastSourcePort
                case .name(let secondPortString):
                    guard let firstSourcePort = tempFirstSourcePort, let sourcePortOperator = tempSourcePortOperator, sourcePortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondSourcePort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondSourcePort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let sourcePortRange = PortRange(minPort: firstSourcePort, maxPort: secondSourcePort) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [sourcePortRange]
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment, .established, .addressV6,.log, .portgroup,.number, .name:
                    reportError()
                    return nil
                case .any:
                    let ipRange = AccessControlEntry.ANYIPV6RANGE
                    self.destIp = [ipRange]
                    linePosition = .destIp
                case .host:
                    linePosition = .destIpHost
                case .addrgroup:
                    linePosition = .destAddrgroup
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destAddrgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.addressV6,.cidrV6,.number:
                    reportError()
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = destObjectGroup.ipRanges
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .addressV6, .cidrV6, .number, .addrgroup,.name:
                    reportError()
                    return nil
                case .portOperator(let destPortOperator):
                    tempDestPortOperator = destPortOperator
                    linePosition = .destPortOperator
                case .comment, .log:
                    linePosition = .end
                case .portgroup:
                    linePosition = .destPortgroup
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol, .any, .host, .portOperator,.comment, .log, .established,.cidrV6, .number, .addrgroup,.portgroup,.name:
                    reportError()
                    return nil
                case .addressV6(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv6)
                    self.destIp = [ipRange]
                    linePosition = .destIp
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .addrgroup,.portgroup,.established, .log, .addressV6, .cidrV6, .comment:
                    reportError()
                    return nil
                case .number(let firstPortNumber):
                    
                    guard analyzeFirstDestPort(firstPort: firstPortNumber) else {
                        reportError()
                        return nil
                    }
                    
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                }
            case .destPortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .addrgroup, .portgroup,.portOperator,.comment, .log, .established,.addressV6,.cidrV6,.number:
                    reportError()
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard destObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Empty port object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destPort = destObjectGroup.portRanges
                    linePosition = .lastDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host, .portOperator, .addrgroup,.portgroup,.comment, .log, .established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .number(let lastDestPort):
                    guard lastDestPort >= 0,
                        lastDestPort <= MAXPORT,
                        let firstDestPort = tempFirstDestPort,
                        let destPortOperator = tempDestPortOperator,
                        destPortOperator == .range,
                        let portRange = PortRange(minPort: firstDestPort, maxPort: lastDestPort) else {
                            reportError()
                            return nil
                    }
                    self.destPort = [portRange]
                    linePosition = .lastDestPort
                case .name(let secondPortString):
                    guard let firstDestPort = tempFirstDestPort, let destPortOperator = tempDestPortOperator, destPortOperator == .range, let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    let secondDestPort: UInt
                    switch ipProtocol {
                    case 6:
                        guard let secondPortOptional = secondPortString.tcpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    case 17:
                        guard let secondPortOptional = secondPortString.udpPort(deviceType: .nxos, delegate: errorDelegate, delegateWindow: delegateWindow) else {
                            reportError()
                            return nil
                        }
                        secondDestPort = secondPortOptional
                    default:
                        reportError()
                        return nil
                    }
                    guard let destPortRange = PortRange(minPort: firstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort = [destPortRange]
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any, .host, .portOperator, .addressV6, .addrgroup,.portgroup,.cidrV6, .number, .name:
                    reportError()
                    return nil
                case .comment, .log:
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                    linePosition = .end
                }
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .addrgroup:
                    break
                case .portgroup:
                    break
                case .action(_):
                    break
                case .ipProtocol(_):
                    break
                case .any:
                    break
                case .host:
                    break
                case .portOperator(_):
                    break
                case .comment:
                    break
                case .log:
                    break
                case .established:
                    guard self.ipProtocols.count == 1 && self.ipProtocols.first == 6 else {
                        reportError()
                        return nil
                    }
                    self.established = true
                case .addressV6(_):
                    break
                case .cidrV6(_):
                    break
                case .number(_):
                    break
                case .name(_):
                    break
                }
            }
        }
        if validateNxos() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }
    
    //MARK: WAS IOSXE IPV4 INIT
    
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, ios: Bool) {
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: IosLinePosition = .beginning
        var tempSourceIp: UInt128?
        var tempDestIp: UInt128?
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }
        
        
        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }
        
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }
        
        func validateIosXe() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
                        
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
                if self.established == true { return false }
            default:
                // should not get here
                return false
            }
            
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }
            
            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            return true
        }
        
        
        wordLoop: for word in words {
            guard let token = IosToken(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .portOperator, .log, .established, .fourOctet, .name,.objectGroup:
                    reportError()
                    return nil
                case .comment:
                    return nil
                case .number(let sequence):
                    self.sequence = sequence
                    linePosition = .sequence
                case .accessList:
                    linePosition = .accessList
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .portOperator, .log, .established, .fourOctet, .number, .name,.objectGroup:
                    reportError()
                    return nil
                case .comment:
                    return nil
                case .accessList:
                    linePosition = .accessList
                }
            case .accessList:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList, .action,.ipProtocol,.any,.host,.objectGroup,.portOperator,.comment,.log,.established,.fourOctet:
                    reportError()
                    return nil
                case .number(let number):
                    self.listName = String(number)
                    aclDelegate?.foundName(String(number), delegateWindow: delegateWindow)
                    linePosition = .listName
                case .name(let name):
                    self.listName = name
                    linePosition = .listName
                }
            case .listName:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .portOperator, .log, .established, .fourOctet, .name,.objectGroup,.accessList,.number:
                    reportError()
                    return nil
                case .comment:
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .portOperator, .comment, .log, .established, .name,.fourOctet,.host,.any,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    guard ipProtocol < 256 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portOperator, .comment, .log, .established, .number, .name,.accessList:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [ANYIPRANGE]
                    linePosition = .sourceMask
                case .host:
                    linePosition = .sourceIpHost
                case .fourOctet(let sourceIp):
                    tempSourceIp = sourceIp
                    linePosition = .sourceIp
                case .objectGroup:
                    linePosition = .sourceNetgroup
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .portOperator, .comment,.log,.established,.number,.name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .fourOctet(let dontCareBit):
                    guard let tempSourceIp = tempSourceIp, let sourceIp = IpRange(ipv4: tempSourceIp, dontCare: dontCareBit) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Possible discontiguous do-not-care-bits after \(linePosition) THIS LINE WILL NOT BE INCLUDED IN ANALYSIS", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = [sourceIp]
                    linePosition = .sourceMask
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host,.portOperator,.comment,.log, .established,.number,.name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .fourOctet(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceMask
                }
            case .sourceNetgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.portOperator,.comment,.log, .established,.fourOctet,.number,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup.ipRanges
                    linePosition = .sourceMask
                }
            case .sourceMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.comment,.log, .established,.number,.name,.accessList:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [ANYIPRANGE]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .portOperator(let sourcePortOperator):
                    tempSourcePortOperator = sourcePortOperator
                    linePosition = .sourcePortOperator
                case .fourOctet(let destIp):
                    tempDestIp = destIp
                    linePosition = .destIp
                case .objectGroup:
                    linePosition = .destNetgroup
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host,.portOperator,.comment,.log, .established,.fourOctet,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                // line position set in analyzeFirstSourcePort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log, .established,.fourOctet,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .number(let port):
                    guard let tempFirstSourcePort = tempFirstSourcePort, port <= MAXPORT, tempSourcePortOperator == .range, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                case .name(let name):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = name.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = name.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstSourcePort = tempFirstSourcePort, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portOperator,.comment,.log,.established,.number,.name,.accessList:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [ANYIPRANGE]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .objectGroup:
                    linePosition = .destNetgroup
                case .fourOctet(let ipNumber):
                    tempDestIp = ipNumber
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.number,.name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .fourOctet(let dontCareBit):
                    guard let tempDestIp = tempDestIp, let destIp = IpRange(ipv4: tempDestIp, dontCare: dontCareBit) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Possible discontiguous do-not-care-bits after \(linePosition) THIS LINE WILL NOT BE INCLUDED IN ANALYSIS", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = [destIp]
                    linePosition = .destMask
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.portOperator,.comment,.log,.established,.number,.name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .fourOctet(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destMask
                }
            case .destNetgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .portOperator,.comment,.log,.established,.fourOctet,.number,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = destObjectGroup.ipRanges
                    linePosition = .destMask
                }
            case .destMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .fourOctet,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .name(let possibleIcmpMessage):
                    guard self.ipProtocols.first == 1, let icmpMessage = IcmpMessage(deviceType: deviceType, message: possibleIcmpMessage) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .number(let possibleIcmpType):
                    guard self.ipProtocols.first == 1, possibleIcmpType < 256, let icmpMessage = IcmpMessage(type: possibleIcmpType, code: nil) else {
                        reportError()
                        return nil
                    }
                    // temporarly assume icmp code is 0 and save it.  if we get a code we will rewrite
                    // this only works if one and only one icmp message can come in on a config line
                    self.icmpMessages = [icmpMessage]
                    linePosition = .icmpType
                case .portOperator(let portOperator):
                    tempDestPortOperator = portOperator
                    linePosition = .destPortOperator
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .icmpType:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.portOperator,.established,.fourOctet,.name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .number(let possibleIcmpCode):
                    guard possibleIcmpCode < 256, let placeholderIcmp = self.icmpMessages.first, let newIcmp = IcmpMessage(type: placeholderIcmp.type, code: possibleIcmpCode) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [newIcmp]  // assumes only one icmp message per line
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .portOperator, .comment, .log, .established, .fourOctet, .objectGroup,.accessList:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstDestPort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                // line position set in analyzeFirstDestPort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .portOperator, .comment, .log, .established, .fourOctet,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .number(let secondDestPort):
                    guard let tempFirstDestPort = tempFirstDestPort, secondDestPort <= MAXPORT, tempDestPortOperator == .range, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                case .name(let secondPortString):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = secondPortString.tcpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = secondPortString.udpPort(deviceType: .ios, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstDestPort = tempFirstDestPort, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .portOperator, .fourOctet, .number, .name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .flags:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .portOperator, .fourOctet, .number, .name,.objectGroup,.accessList:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .comment:
                linePosition = .comment
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.portOperator,.established,.fourOctet,.number,.name,.accessList,.objectGroup:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            }
        }// wordLoop
        if validateIosXe() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }//Init IOS and IOS-XE
    }

    //MARK: IOSXR IPV4 INIT
    
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, iosxr: Bool) {
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: IosXrLinePosition = .beginning
        var tempSourceIp: UInt128?
        var tempDestIp: UInt128?
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }

        
        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }
        
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }

        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }
        
        func validateIosXr() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
                        
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
                if self.established == true { return false }
            default:
                // should not get here
                return false
            }
            
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }
            
            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }

            return true
        }


        wordLoop: for word in words {
            guard let token = IosXrToken(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .netgroup, .portgroup, .portOperator, .log, .established, .counter, .fourOctet, .cidr, .name:
                    reportError()
                    return nil
                case .comment:
                    return nil
                case .number(let sequence):
                    self.sequence = sequence
                    linePosition = .sequence
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .netgroup, .portgroup, .portOperator, .log, .counter, .established, .fourOctet, .cidr, .number, .name:
                    reportError()
                    return nil
                case .comment:
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .portgroup, .portOperator, .comment, .log,.counter, .established, .name, .netgroup:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    guard ipProtocol < 256 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .fourOctet(let sourceIp):
                    //this means this is the short "source address only" mode
                    tempSourceIp = sourceIp
                    linePosition = .sourceIpOnly
                case .cidr(let sourceIpRange):
                    //this means this is the short "source address only" mode
                    self.sourceIp = [sourceIpRange]
                    self.destIp = [ANYIPRANGE]
                    self.ipProtocols = [0]
                    linePosition = .end
                case .host:
                    //this means this is the short "source address only" mode
                    linePosition = .sourceIpHostOnly
                case .any:
                    //this means this is the short "source address only" mode with a permit any
                    let ipRange = IpRange(minIp: 0, maxIp: MAXIP, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    self.destIp = [ipRange]
                    self.ipProtocols = [0]
                    linePosition = .end
                }
            case .sourceIpOnly:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                    
                case .fourOctet(let dontCareBit):
                    guard let tempSourceIp = tempSourceIp, let sourceIp = IpRange(ipv4: tempSourceIp, dontCare: dontCareBit) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Possible discontiguous do-not-care-bits after \(linePosition) THIS LINE WILL NOT BE INCLUDED IN ANALYSIS", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = [sourceIp]
                    let destIpRange = ANYIPRANGE
                    self.destIp = [destIpRange]
                    self.ipProtocols = [0]
                    linePosition = .end
                case .action(_), .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log, .established, .cidr, .counter, .number, .name:
                    reportError()
                    return nil
                }
            case .sourceIpHostOnly:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                    
                case .fourOctet(let sourceIp):
                    guard sourceIp <= MAXIP else {
                        reportError()
                        return nil
                    }
                    let sourceIpRange = IpRange(minIp: sourceIp, maxIp: sourceIp, ipVersion: .IPv4)
                    self.sourceIp = [sourceIpRange]
                    self.destIp = [ANYIPRANGE]
                    self.ipProtocols = [0]
                    linePosition = .end
                case .action(_), .ipProtocol, .any, .host, .netgroup, .portgroup,.portOperator, .comment, .log, .established, .cidr, .counter, .number, .name:
                    reportError()
                    return nil
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portgroup, .portOperator, .comment, .log, .counter, .established, .number, .name:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [ANYIPRANGE]
                    linePosition = .sourceMask
                case .host:
                    linePosition = .sourceIpHost
                case .netgroup:
                    linePosition = .sourceNetgroup
                case .fourOctet(let sourceIp):
                    tempSourceIp = sourceIp
                    linePosition = .sourceIp
                case .cidr(let sourceIpRange):
                    self.sourceIp = [sourceIpRange]
                    linePosition = .sourceMask
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .counter, .portOperator, .comment,.log,.established,.cidr,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let dontCareBit):
                    guard let tempSourceIp = tempSourceIp, let sourceIp = IpRange(ipv4: tempSourceIp, dontCare: dontCareBit) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Possible discontiguous do-not-care-bits after \(linePosition) THIS LINE WILL NOT BE INCLUDED IN ANALYSIS", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = [sourceIp]
                    linePosition = .sourceMask
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.cidr,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceMask
                }
            case .sourceNetgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.fourOctet,.cidr,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup.ipRanges
                    linePosition = .sourceMask
                }
            case .sourceMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.comment,.log,.counter, .established,.number,.name:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [ANYIPRANGE]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .netgroup:
                    linePosition = .destNetgroup
                case .portgroup:
                    linePosition = .sourcePortgroup
                case .portOperator(let sourcePortOperator):
                    tempSourcePortOperator = sourcePortOperator
                    linePosition = .sourcePortOperator
                case .fourOctet(let destIp):
                    tempDestIp = destIp
                    linePosition = .destIp
                case .cidr(let destIpRange):
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup,.portOperator,.comment,.log,.counter, .established,.fourOctet,.cidr:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.fourOctet,.cidr:
                    reportError()
                    return nil
               case .number(let port):
                    guard let tempFirstSourcePort = tempFirstSourcePort, port <= MAXPORT, tempSourcePortOperator == .range, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                case .name(let name):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = name.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = name.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstSourcePort = tempFirstSourcePort, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                }
            case .sourcePortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.fourOctet,.cidr,.number:
                    reportError()
                    return nil
                //TODO: could a number or fourOctet be valid portgroup names?  If yes need to add some cases
                case .name(let objectName):
                    guard let serviceObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown port-group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard serviceObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Cannot use empty port-group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourcePort = serviceObjectGroup.portRanges
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portgroup,.portOperator,.comment,.log,.counter,.established,.cidr,.number,.name:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [ANYIPRANGE]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .netgroup:
                    linePosition = .destNetgroup
                case .fourOctet(let ipNumber):
                    tempDestIp = ipNumber
                    linePosition = .destIp
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter,.established,.cidr,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let dontCareBit):
                    guard let tempDestIp = tempDestIp, let destIp = IpRange(ipv4: tempDestIp, dontCare: dontCareBit) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Possible discontiguous do-not-care-bits after \(linePosition) THIS LINE WILL NOT BE INCLUDED IN ANALYSIS", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = [destIp]
                    linePosition = .destMask
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter,.established,.cidr,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv4)
                    self.destIp = [ipRange]
                    linePosition = .destMask
                }
            case .destNetgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup,.portOperator,.comment,.log,.counter,.established,.fourOctet,.cidr,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = destObjectGroup.ipRanges
                    linePosition = .destMask
                }
            case .destMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .fourOctet,.cidr:
                    reportError()
                    return nil
                case .name(let possibleIcmpMessage):
                    guard self.ipProtocols.first == 1, let icmpMessage = IcmpMessage(deviceType: deviceType, message: possibleIcmpMessage) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .number(let possibleIcmpType):
                    guard self.ipProtocols.first == 1, possibleIcmpType < 256, let icmpMessage = IcmpMessage(type: possibleIcmpType, code: nil) else {
                        reportError()
                        return nil
                    }
                    // temporarly assume icmp code is 0 and save it.  if we get a code we will rewrite
                    // this only works if one and only one icmp message can come in on a config line
                    self.icmpMessages = [icmpMessage]
                    linePosition = .icmpType
                case .portgroup:
                    linePosition = .destPortgroup
                case .portOperator(let portOperator):
                    tempDestPortOperator = portOperator
                    linePosition = .destPortOperator
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .counter:
                    linePosition = .counter
                case .established:
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .icmpType:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.established,.fourOctet,.cidr,.name:
                    reportError()
                    return nil
                case .number(let possibleIcmpCode):
                    guard possibleIcmpCode < 256, let placeholderIcmp = self.icmpMessages.first, let newIcmp = IcmpMessage(type: placeholderIcmp.type, code: possibleIcmpCode) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [newIcmp]  // assumes only one icmp message per line
                case .counter:
                    guard self.counter == false else {
                        reportError()
                        return nil
                    }
                    self.counter = true
                    linePosition = .counter
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log,.counter, .established, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstDestPort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                }
            case .destPortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log,.counter, .established, .fourOctet, .cidr, .number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard destObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Empty port object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destPort = destObjectGroup.portRanges
                    linePosition = .lastDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log,.counter, .established, .fourOctet, .cidr:
                    reportError()
                    return nil
                case .number(let secondDestPort):
                    guard let tempFirstDestPort = tempFirstDestPort, secondDestPort <= MAXPORT, tempDestPortOperator == .range, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                case .name(let secondPortString):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = secondPortString.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = secondPortString.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstDestPort = tempFirstDestPort, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .fourOctet, .cidr, .number, .name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .counter:
                    linePosition = .counter
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .flags:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .fourOctet, .cidr, .number, .name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .counter:
                    linePosition = .counter
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .counter:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.counter,.portgroup,.portOperator,.comment,.log,.established,.fourOctet,.cidr,.number:
                    reportError()
                    return nil
                case .name(_):
                    linePosition = .end
                }
            case .comment:
                linePosition = .comment
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.established,.fourOctet,.cidr,.number,.name:
                    reportError()
                    return nil
                case .counter:
                    guard self.counter == false else {
                        reportError()
                        return nil
                    }
                    self.counter = true
                    linePosition = .counter
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            }
        }// wordLoop
        if validateIosXr() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }//Init IOS-XR IPV4
    
    //MARK: IOSXR IPV6 INIT
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, iosxrv6: Bool) {
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: IosXrLinePosition = .beginning
        var tempSourceIp: UInt128?
        var tempDestIp: UInt128?
        
        self.line = line
        self.linenum = linenum
        
        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }
        
        
        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }
        
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }
        func validateIosXr() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
                        
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            if self.ipProtocols.count != 1 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
                if self.established == true { return false }
            default:
                // should not get here
                return false
            }
            
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
            }
            
            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            
            return true
        }

        wordLoop: for word in words {
            guard let token = IosXrTokenV6(string: word) else {
                reportError()
                return nil
            }
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .netgroup, .portgroup, .portOperator, .log, .established, .counter, .addressV6, .cidrV6, .name:
                    reportError()
                    return nil
                case .comment:
                    return nil
                case .number(let sequence):
                    self.sequence = sequence
                    linePosition = .sequence
                }
            case .sequence:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                case .ipProtocol(_), .any, .host, .netgroup, .portgroup, .portOperator, .log, .counter, .established, .addressV6, .cidrV6, .number, .name:
                    reportError()
                    return nil
                case .comment:
                    return nil
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .portgroup, .portOperator, .comment, .log,.counter, .established, .name, .addressV6,.netgroup:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    guard ipProtocol < 256 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .number(let ipProtocol):
                    guard ipProtocol < 256 && ipProtocol > 0 else {
                        reportError()
                        return nil
                    }
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .cidrV6(let sourceIpRange):
                    //this means this is the short "source address only" mode
                    self.sourceIp = [sourceIpRange]
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    self.ipProtocols = [0]
                    linePosition = .end
                case .host:
                    //this means this is the short "source address only" mode
                    linePosition = .sourceIpHostOnly
                case .any:
                    //this means this is the short "source address only" mode with a permit any
                    let ipRange = AccessControlEntry.ANYIPV6RANGE
                    self.sourceIp = [ipRange]
                    self.destIp = [ipRange]
                    self.ipProtocols = [0]
                    linePosition = .end
                }
            case .sourceIpOnly:
                //should not get here for IPv6 case
                reportError()
                return nil
            case .sourceIpHostOnly:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                    
                case .addressV6(let sourceIp):
                    let sourceIpRange = IpRange(minIp: sourceIp, maxIp: sourceIp, ipVersion: .IPv6)
                    self.sourceIp = [sourceIpRange]
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    self.ipProtocols = [0]
                    linePosition = .end
                case .action(_), .ipProtocol, .any, .host, .netgroup, .portgroup,.portOperator, .comment, .log, .established, .cidrV6, .counter, .number, .name:
                    reportError()
                    return nil
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .portgroup, .portOperator, .comment, .log, .counter, .established, .addressV6, .number, .name:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .sourceMask
                case .host:
                    linePosition = .sourceIpHost
                case .netgroup:
                    linePosition = .sourceNetgroup
                /*case .addressV6(let sourceIp):
                    tempSourceIp = sourceIp
                    linePosition = .sourceIp*/
                case .cidrV6(let sourceIpRange):
                    self.sourceIp = [sourceIpRange]
                    linePosition = .sourceMask
                }
            case .sourceIp:
                //should not get here for IPv6 case
                reportError()
                return nil
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_), .ipProtocol, .any, .host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .addressV6(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv6)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceMask
                }
            case .sourceNetgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action(_),.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.addressV6,.cidrV6,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup.ipRanges
                    linePosition = .sourceMask
                }
            case .sourceMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.comment,.log,.counter, .established,.number,.addressV6,.name:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .netgroup:
                    linePosition = .destNetgroup
                case .portgroup:
                    linePosition = .sourcePortgroup
                case .portOperator(let sourcePortOperator):
                    tempSourcePortOperator = sourcePortOperator
                    linePosition = .sourcePortOperator
                /*case .fourOctet(let destIp):
                    tempDestIp = destIp
                    linePosition = .destIp*/
                case .cidrV6(let destIpRange):
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup,.portOperator,.comment,.log,.counter, .established,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstSourcePort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                // line position set in analyzeFirstSourcePort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstSourcePort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let port):
                    guard let tempFirstSourcePort = tempFirstSourcePort, port <= MAXPORT, tempSourcePortOperator == .range, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                case .name(let name):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = name.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = name.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstSourcePort = tempFirstSourcePort, let sourcePort = PortRange(minPort: tempFirstSourcePort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort.append(sourcePort)
                    linePosition = .lastSourcePort
                }
            case .sourcePortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter, .established,.addressV6,.cidrV6,.number:
                    reportError()
                    return nil
                //TODO: could a number or fourOctet be valid portgroup names?  If yes need to add some cases
                case .name(let objectName):
                    guard let serviceObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown port-group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard serviceObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Cannot use empty port-group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourcePort = serviceObjectGroup.portRanges
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.portgroup,.portOperator,.comment,.log,.counter,.established,.addressV6,.number,.name:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .netgroup:
                    linePosition = .destNetgroup
                case .cidrV6(let destIpRange):
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                }
            case .destIp:
                //should not get here for ipv6 case
                reportError()
                return nil
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action,.ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.comment,.log,.counter,.established,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .addressV6(let ipHost):
                    let ipRange = IpRange(minIp: ipHost, maxIp: ipHost, ipVersion: .IPv6)
                    self.destIp = [ipRange]
                    linePosition = .destMask
                }
            case .destNetgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup,.portOperator,.comment,.log,.counter,.established,.addressV6,.cidrV6,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destIp = destObjectGroup.ipRanges
                    linePosition = .destMask
                }
            case .destMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .addressV6,.cidrV6:
                    reportError()
                    return nil
                case .name(let possibleIcmpMessage):
                    guard self.ipProtocols.first == 1, let icmpMessage = IcmpMessage(deviceType: deviceType, message: possibleIcmpMessage) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                case .number(let possibleIcmpType):
                    guard self.ipProtocols.first == 1, possibleIcmpType < 256, let icmpMessage = IcmpMessage(type: possibleIcmpType, code: nil) else {
                        reportError()
                        return nil
                    }
                    // temporarly assume icmp code is 0 and save it.  if we get a code we will rewrite
                    // this only works if one and only one icmp message can come in on a config line
                    self.icmpMessages = [icmpMessage]
                    linePosition = .icmpType
                case .portgroup:
                    linePosition = .destPortgroup
                case .portOperator(let portOperator):
                    tempDestPortOperator = portOperator
                    linePosition = .destPortOperator
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .counter:
                    linePosition = .counter
                case .established:
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .icmpType:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.established,.addressV6,.cidrV6,.name:
                    reportError()
                    return nil
                case .number(let possibleIcmpCode):
                    guard possibleIcmpCode < 256, let placeholderIcmp = self.icmpMessages.first, let newIcmp = IcmpMessage(type: placeholderIcmp.type, code: possibleIcmpCode) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [newIcmp]  // assumes only one icmp message per line
                case .counter:
                    guard self.counter == false else {
                        reportError()
                        return nil
                    }
                    self.counter = true
                    linePosition = .counter
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log,.counter, .established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .number(let firstPort):
                    guard analyzeFirstDestPort(firstPort: firstPort) else {
                        reportError()
                        return nil
                    }
                // line position set in analyzeFirstDestPort
                case .name(let firstStringPort):
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        guard let firstPort = firstStringPort.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    case 17:
                        guard let firstPort = firstStringPort.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow), analyzeFirstDestPort(firstPort: firstPort) else {
                            reportError()
                            return nil
                        }
                    default:
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstDestPort
                }
            case .destPortgroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log,.counter, .established, .addressV6, .cidrV6, .number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let destObjectGroup = aclDelegate?.getObjectGroupService(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    guard destObjectGroup.portRanges.count > 0 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Empty port object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.destPort = destObjectGroup.portRanges
                    linePosition = .lastDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .comment, .log,.counter, .established, .addressV6, .cidrV6:
                    reportError()
                    return nil
                case .number(let secondDestPort):
                    guard let tempFirstDestPort = tempFirstDestPort, secondDestPort <= MAXPORT, tempDestPortOperator == .range, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                case .name(let secondPortString):
                    var possiblePort: UInt?
                    if self.ipProtocols.count > 1 {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .warning, message: "Unexpectedly found multiple ipProtocols for \(deviceType) after \(linePosition).  Please send this case to feedback@networkmom.net.  Analysis of this line may not be accurate.", line: linenum, delegateWindow: delegateWindow)
                    }
                    guard let ipProtocol = self.ipProtocols.first else {
                        reportError()
                        return nil
                    }
                    switch ipProtocol {
                    case 6:
                        if let tempPort = secondPortString.tcpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    case 17:
                        if let tempPort = secondPortString.udpPort(deviceType: .iosxr, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tempPort
                        }
                    default:
                        break // error dealt with with next test since possiblePort is still nil
                    }
                    guard let port = possiblePort, let tempFirstDestPort = tempFirstDestPort, let destPort = PortRange(minPort: tempFirstDestPort, maxPort: port) else {
                        reportError()
                        return nil
                    }
                    self.destPort.append(destPort)
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .addressV6, .cidrV6, .number, .name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .counter:
                    linePosition = .counter
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .flags:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol, .any, .host, .netgroup, .portgroup, .portOperator, .addressV6, .cidrV6, .number, .name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .counter:
                    linePosition = .counter
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                case .established:
                    guard self.established == false else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Error: found established keyword twice", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    guard self.ipProtocols.count == 1, let ipProtocol = self.ipProtocols.first, ipProtocol == 6 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Established only has meaning when IP Protocol is tcp", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.established = true
                    linePosition = .flags
                }
            case .counter:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.counter,.portgroup,.portOperator,.comment,.log,.established,.addressV6,.cidrV6,.number:
                    reportError()
                    return nil
                case .name(_):
                    linePosition = .end
                }
            case .comment:
                linePosition = .comment
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .action, .ipProtocol,.any,.host,.netgroup,.portgroup,.portOperator,.established,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .counter:
                    guard self.counter == false else {
                        reportError()
                        return nil
                    }
                    self.counter = true
                    linePosition = .counter
                case .comment:
                    linePosition = .comment
                case .log:
                    guard self.log == false else {
                        reportError()
                        return nil
                    }
                    self.log = true
                    linePosition = .end
                }
            }
        }// wordLoop
        if validateIosXr() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }//Init IOS-XR IPV6
    
    
    //MARK: ASA
    init?(line: String, deviceType: DeviceType, linenum: Int, aclDelegate: AclDelegate? = nil, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?, asa: Bool) {
        var tempSourcePortOperator: PortOperator?
        var tempFirstSourcePort: UInt?
        var tempDestPortOperator: PortOperator?
        var tempFirstDestPort: UInt?
        var linePosition: AsaLinePosition = .beginning
        var tempSourceIp: UInt128?
        var tempDestIp: UInt128?
        
        self.line = line
        self.linenum = linenum
        
        func validateAsa() -> Bool { // true -> ACE validated
            if self.aclAction == .neither { return false }
                        
            if self.sourceIp.count == 0 { return false }
            if self.destIp.count == 0 { return false }
            guard let ipProtocol = self.ipProtocols.first else { return false }
            
            switch ipProtocol {
            case 6:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                break
            case 17:
                if self.sourcePort.count == 0 {
                    self.sourcePort.append(ANYPORTRANGE)
                }
                if self.destPort.count == 0 {
                    self.destPort.append(ANYPORTRANGE)
                }
                if self.established == true { return false }
            case 0...255:
                if self.sourcePort.count > 0 || self.destPort.count > 0 {  // only protocols 6 and 17 have ports
                    return false
                }
            default:
                // should not get here
                return false
            }
            
            var sourceAllBitAligned = true
            var destAllBitAligned = true
            
            var sourceAllIpv4 = true
            var sourceAllIpv6 = true
            var destAllIpv4 = true
            var destAllIpv6 = true
            
            for ipRange in self.sourceIp {
                if ipRange.bitAligned == false {
                    sourceAllBitAligned = false
                }
                if ipRange.ipVersion == .IPv4 {
                    sourceAllIpv6 = false
                }
                if ipRange.ipVersion == .IPv6 {
                    sourceAllIpv4 = false
                }
            }
            for ipRange in self.destIp {
                if ipRange.bitAligned == false {
                    destAllBitAligned = false
                }
                if ipRange.ipVersion == .IPv4 {
                    destAllIpv6 = false
                }
                if ipRange.ipVersion == .IPv6 {
                    destAllIpv4 = false
                }
            }
            
            if sourceAllIpv4 && destAllIpv6 {
                return false
            }
            if sourceAllIpv6 && destAllIpv4 {
                return false
            }
            
            if !sourceAllBitAligned || !destAllBitAligned {
                errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            }
            if !sourceAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Source IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }
            if !destAllBitAligned {
                errorDelegate?.report(severity: .warning, message: "Destination IP not on netmask or bit boundary", line: linenum, delegateWindow: delegateWindow)
            }

            return true
        }

        func reportError() {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "invalid after \(linePosition)", line: linenum, delegateWindow: delegateWindow)
        }
        
        func reportUnsupported(keyword: String) {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "keyword \(keyword) for \(deviceType) after \(linePosition) not supported by ACL analyzer, not included in analysis.", line: linenum, delegateWindow: delegateWindow)
        }

        let line = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        let words = line.split{ $0.isWhitespace }.map{ String($0)}
        if words.count < 1 {
            return nil
        }
        
        //TODO review
        func analyzeFirstSourcePort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempSourcePortOperator = tempSourcePortOperator else {
                return false
            }
            switch tempSourcePortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                sourcePort = [portRange]
                linePosition = .lastSourcePort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                sourcePort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastSourcePort
            case .range:
                tempFirstSourcePort = firstPort
                linePosition = .firstSourcePort
            }
            return true
        }
        
        //TODO review
        func analyzeFirstDestPort(firstPort: UInt) -> Bool { // true == success
            guard firstPort >= 0 && firstPort <= 65535, let tempDestPortOperator = tempDestPortOperator else {
                return false
            }
            switch tempDestPortOperator {
                
            case .eq:
                guard let portRange = PortRange(minPort: firstPort, maxPort: firstPort) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .gt:
                guard let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .lt:
                guard firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) else {
                    return false
                }
                destPort = [portRange]
                linePosition = .lastDestPort
            case .ne:
                var portRange1: PortRange? = nil
                if firstPort > 0 {
                    portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1)
                }
                let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT)
                destPort = [portRange1,portRange2].compactMap({ $0 })
                linePosition = .lastDestPort
            case .range:
                tempFirstDestPort = firstPort
                linePosition = .firstDestPort
            }
            return true
        }

        wordLoop: for word in words {
            guard let token = AsaToken(string: word) else {
                reportError()
                return nil
            }
            
            switch linePosition {
            case .beginning:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .extended,.action,.ipProtocol,.any,.any4,.any6,.host,.objectGroup,.portOperator,.log,.fourOctet,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .accessList:
                    linePosition = .accessList
                case .comment:
                    return nil
                }
            case .accessList:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.objectGroup,.portOperator,.comment,.log,.fourOctet,.addressV6,.cidrV6:
                    reportError()
                    return nil
                case .number(let listNumber):
                    let listName = String(listNumber)
                    self.listName = listName
                    aclDelegate?.foundName(listName, delegateWindow: delegateWindow)
                    linePosition = .listName
                case .name(let listName):
                    self.listName = listName
                    aclDelegate?.foundName(listName,delegateWindow: delegateWindow)
                    linePosition = .listName
                }
            case .listName:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.action,.ipProtocol,.any,.any4,.any6,.host,.objectGroup,.portOperator,.log,.fourOctet,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .extended:
                    linePosition = .extended
                case .comment:
                    return nil
                }
            case .extended:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.ipProtocol,.any,.any4,.any6,.host,.objectGroup,.portOperator,.comment,.log,.fourOctet,.addressV6,.cidrV6,.number,.name:
                    reportError()
                    return nil
                case .action(let action):
                    self.aclAction = action
                    linePosition = .action
                }
            case .action:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.any,.any4,.any6,.host,.portOperator,.comment,.log,.fourOctet,.addressV6,.cidrV6,.name:
                    reportError()
                    return nil
                case .ipProtocol(let ipProtocol):
                    self.ipProtocols = [ipProtocol]
                    linePosition = .ipProtocol
                case .objectGroup:
                    linePosition = .protocolObjectGroup
                case .number(let possibleIpProtocol):
                    guard possibleIpProtocol > 0 && possibleIpProtocol < 256 else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "IP Protocol must be between 1 and 255 inclusive", line: linenum, delegateWindow: delegateWindow)
                        return nil
                    }
                    self.ipProtocols = [possibleIpProtocol]
                    linePosition = .ipProtocol
                }
            case .protocolObjectGroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet:
                    reportError()
                    return nil
                case .number(let objectGroupNumber):
                    let objectGroupName = String(objectGroupNumber)
                    guard let protocolObjectGroup = aclDelegate?.getObjectGroupProtocol(objectGroupName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectGroupName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.ipProtocols = protocolObjectGroup.ipProtocols
                    linePosition = .ipProtocol
                case .name(let objectGroupName):
                    guard let protocolObjectGroup = aclDelegate?.getObjectGroupProtocol(objectGroupName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectGroupName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.ipProtocols = protocolObjectGroup.ipProtocols
                    linePosition = .ipProtocol
                }
            case .ipProtocol:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.portOperator,.addressV6,.comment,.log,.number:
                    reportError()
                    return nil
                case .any:
                    self.sourceIp = [ANYIPRANGE,AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .sourceMask
                case .any4:
                    self.sourceIp = [ANYIPRANGE]
                    linePosition = .sourceMask
                case .any6:
                    self.sourceIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .sourceMask
                case .cidrV6(let sourceIpv6Range):
                    self.sourceIp = [sourceIpv6Range]
                    linePosition = .sourceMask
                case .host:
                    linePosition = .sourceIpHost
                case .objectGroup:
                    linePosition = .sourceObjectGroup
                case .fourOctet(let sourceIp):
                    tempSourceIp = sourceIp
                    linePosition = .sourceIp
                case .name(let possibleHostname):
                    guard let sourceIp = aclDelegate?.getHostname(possibleHostname) else {
                        reportError()
                        return nil
                    }
                    tempSourceIp = sourceIp
                    linePosition = .sourceIp
                }
            case .sourceIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.number,.name:
                    reportError()
                    return nil
                case .fourOctet(let sourceNetmask):
                    guard let tempSourceIp = tempSourceIp, let sourceIpRange = IpRange(ip: tempSourceIp, netmask: sourceNetmask) else {
                        reportError()
                        return nil
                    }
                    self.sourceIp = [sourceIpRange]
                    linePosition = .sourceMask
                }
            case .sourceIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.cidrV6,.objectGroup,.portOperator,.comment,.log,.number:
                    reportError()
                    return nil
                case .fourOctet(let sourceIp):
                    let ipRange = IpRange(minIp: sourceIp, maxIp: sourceIp, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceMask
                case .addressV6(let sourceIp):
                    let ipRange = IpRange(minIp: sourceIp, maxIp: sourceIp, ipVersion: .IPv6)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceMask
                case .name(let possibleHostname):
                    guard let sourceIp = aclDelegate?.getHostname(possibleHostname) else {
                        reportError()
                        return nil
                    }
                    let ipRange = IpRange(minIp: sourceIp, maxIp: sourceIp, ipVersion: .IPv4)
                    self.sourceIp = [ipRange]
                    linePosition = .sourceMask
                }
            case .sourceObjectGroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.cidrV6,.addressV6,.objectGroup,.portOperator,.comment,.log,.fourOctet,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let sourceObjectGroup = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        errorDelegate?.report(severity: .error, message: "Unknown object group \(objectName)", delegateWindow: delegateWindow)
                        return nil
                    }
                    self.sourceIp = sourceObjectGroup.ipRanges
                    linePosition = .sourceMask
                }
            case .sourceMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.comment,.log,.addressV6,.number:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [ANYIPRANGE,AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destMask
                case .any4:
                    self.destIp = [ANYIPRANGE]
                    linePosition = .destMask
                case .any6:
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destMask
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .objectGroup:
                    linePosition = .sourcePortObjectGroup //could be source port or dest ip
                case .portOperator(let portOperator):
                    tempSourcePortOperator = portOperator
                    linePosition = .sourcePortOperator
                case .fourOctet(let destIp):
                    tempDestIp = destIp
                    linePosition = .destIp
                case .name(let possibleDestHostname):
                    guard let destHostIp = aclDelegate?.getHostname(possibleDestHostname) else {
                        reportError()
                        return nil
                    }
                    tempDestIp = destHostIp
                    linePosition = .destIp
                }
            case .sourcePortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet:
                    reportError()
                    return nil
                case .number(let firstSourcePort):
                    guard analyzeFirstSourcePort(firstPort: firstSourcePort) else {
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                case .name(let firstSourcePortString):
                    var possiblePort: UInt? = nil
                    if self.ipProtocols.contains(6) {
                        if let tcpPort = firstSourcePortString.tcpPort(deviceType: .asa, delegate: errorDelegate,delegateWindow: delegateWindow) {
                            possiblePort = tcpPort
                        }
                    }
                    if self.ipProtocols.contains(17) {
                        if let tcpPort = firstSourcePortString.udpPort(deviceType: .asa, delegate: nil, delegateWindow: nil) {
                            possiblePort = tcpPort
                        }
                    }
                    guard let firstSourcePort = possiblePort else {
                        reportError()
                        return nil
                    }
                    guard analyzeFirstSourcePort(firstPort: firstSourcePort) == true else {
                        reportError()
                        return nil
                    }
                    // line position set in analyzeFirstSourcePort
                }
            case .firstSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet:
                    reportError()
                    return nil
                case .number(let secondSourcePort):
                    guard secondSourcePort < MAXPORT, let tempFirstSourcePort = tempFirstSourcePort, let sourcePortRange = PortRange(minPort: tempFirstSourcePort, maxPort: secondSourcePort) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [sourcePortRange]
                    linePosition = .lastSourcePort
                case .name(let secondSourcePortString):
                    var possiblePort: UInt? = nil
                    if self.ipProtocols.contains(6) {
                        if let tcpPort = secondSourcePortString.tcpPort(deviceType: .asa, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possiblePort = tcpPort
                        }
                    }
                    if self.ipProtocols.contains(17) {
                        if let tcpPort = secondSourcePortString.udpPort(deviceType: .asa, delegate: nil, delegateWindow: nil) {
                            possiblePort = tcpPort
                        }
                    }
                    guard let tempFirstSourcePort = tempFirstSourcePort, let secondSourcePort = possiblePort, let sourcePortRange = PortRange(minPort: tempFirstSourcePort, maxPort: secondSourcePort) else {
                        reportError()
                        return nil
                    }
                    self.sourcePort = [sourcePortRange]
                    linePosition = .lastSourcePort
                }
            case .lastSourcePort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.portOperator,.addressV6,.comment,.log,.number:
                    reportError()
                    return nil
                case .any:
                    self.destIp = [ANYIPRANGE,AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destMask
                case .any4:
                    self.destIp = [ANYIPRANGE]
                    linePosition = .destMask
                case .any6:
                    self.destIp = [AccessControlEntry.ANYIPV6RANGE]
                    linePosition = .destMask
                case .cidrV6(let ipRange):
                    self.destIp = [ipRange]
                    linePosition = .destMask
                case .host:
                    linePosition = .destIpHost
                case .objectGroup:
                    linePosition = .destObjectGroup
                case .fourOctet(let destIp):
                    tempDestIp = destIp
                    linePosition = .destIp
                case .name(let destHostname):
                    guard let destIp = aclDelegate?.getHostname(destHostname) else {
                        reportError()
                        return nil
                    }
                    tempDestIp = destIp
                    linePosition = .destIp
                }
            case .sourcePortObjectGroup: //could be source port or dest ip
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    //first check for service object group
                    if let serviceObject = aclDelegate?.getObjectGroupService(objectName) {
                        self.sourcePort = serviceObject.portRanges
                        linePosition = .lastSourcePort
                        //TODO do I need to deal with tcp-udp type?
                    } else if let networkObject = aclDelegate?.getObjectGroupNetwork(objectName) {
                            self.destIp = networkObject.ipRanges
                        linePosition = .destMask
                    } else {
                        reportError()
                        return nil
                    }
                }
            case .destIp:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.number,.name:
                    reportError()
                case .fourOctet(let destNetmask):
                    guard let tempDestIp = tempDestIp, let destIpRange = IpRange(ip: tempDestIp, netmask: destNetmask) else {
                        reportError()
                        return nil
                    }
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                }
            case .destIpHost:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.cidrV6,.objectGroup,.portOperator,.comment,.log,.number:
                    reportError()
                    return nil
                case .fourOctet(let destIp):
                    guard destIp < MAXIP else {
                        //should not get here
                        reportError()
                        return nil
                    }
                    let destIpRange = IpRange(minIp: destIp, maxIp: destIp, ipVersion: .IPv4)
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                case .addressV6(let destIp):
                    let destIpRange = IpRange(minIp: destIp, maxIp: destIp, ipVersion: .IPv6)
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                case .name(let destHostname):
                    guard let destIp = aclDelegate?.getHostname(destHostname) else {
                        reportError()
                        return nil
                    }
                    let destIpRange = IpRange(minIp: destIp, maxIp: destIp, ipVersion: .IPv4)
                    self.destIp = [destIpRange]
                    linePosition = .destMask
                }
            case .destObjectGroup:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let networkObject = aclDelegate?.getObjectGroupNetwork(objectName) else {
                        reportError()
                        return nil
                    }
                    self.destIp = networkObject.ipRanges
                    linePosition = .destMask
                }
            case .destMask:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.addressV6,.cidrV6,.host,.fourOctet:
                    reportError()
                    return nil
                case .objectGroup:
                    linePosition = .destObjectService
                case .portOperator(let portOperator):
                    tempDestPortOperator = portOperator
                    linePosition = .destPortOperator
                case .comment:
                    linePosition = .comment
                case .log:
                    linePosition = .log
                case .number(let possibleIcmpType):
                    guard self.ipProtocols.contains(1), let icmpMessage = IcmpMessage(type: possibleIcmpType) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .icmpType
                case .name(let icmpMessageString):
                    guard self.ipProtocols.contains(1), let icmpMessage = IcmpMessage(deviceType: .asa, message: icmpMessageString) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                    linePosition = .end
                }
            case .icmpType: //icmp code optional so could be log stuff
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.fourOctet,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    linePosition = .log
                case .number(let icmpCode):
                    guard let icmpType = self.icmpMessages.first?.type, let icmpMessage = IcmpMessage(type: icmpType, code: icmpCode) else {
                        reportError()
                        return nil
                    }
                    self.icmpMessages = [icmpMessage]
                }
            case .destPortOperator:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet:
                    reportError()
                    return nil
                case .number(let destPort):
                    guard destPort < MAXPORT else {
                        reportError()
                        return nil
                    }
                    guard analyzeFirstDestPort(firstPort: destPort) else {
                        reportError()
                        return nil
                    }
                    //linePosition set in analyzeFirstDestPort
                case .name(let destPortString):
                    var possibleDestPort: UInt? = nil
                    if self.ipProtocols.contains(6) {
                        if let port = destPortString.tcpPort(deviceType: .asa, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possibleDestPort = port
                        }
                    }
                    if self.ipProtocols.contains(17) {
                        if let port = destPortString.udpPort(deviceType: .asa, delegate: nil, delegateWindow: nil) {
                            possibleDestPort = port
                        }
                    }
                    guard let destPort = possibleDestPort else {
                        reportError()
                        return nil
                    }
                    guard analyzeFirstDestPort(firstPort: destPort) else {
                        reportError()
                        return nil
                    }
                    //linePosition set in analyzeFirstDestPort
                }
            case .firstDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet:
                    reportError()
                    return nil
                case .number(let secondDestPort):
                    guard tempDestPortOperator == .range, let tempFirstDestPort = tempFirstDestPort, let destPortRange = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort = [destPortRange]
                    linePosition = .lastDestPort
                case .name(let secondDestPortString):
                    var possibleSecondDestPort: UInt? = nil
                    if self.ipProtocols.contains(6) {
                        if let port = secondDestPortString.tcpPort(deviceType: .asa, delegate: errorDelegate, delegateWindow: delegateWindow) {
                            possibleSecondDestPort = port
                        }
                    }
                    if self.ipProtocols.contains(17) {
                        if let port = secondDestPortString.udpPort(deviceType: .asa, delegate: nil, delegateWindow: nil) {
                            possibleSecondDestPort = port
                        }
                    }
                    guard let secondDestPort = possibleSecondDestPort, let tempFirstDestPort = tempFirstDestPort, let destPortRange = PortRange(minPort: tempFirstDestPort, maxPort: secondDestPort) else {
                        reportError()
                        return nil
                    }
                    self.destPort = [destPortRange]
                    linePosition = .lastDestPort
                }
            case .lastDestPort:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.fourOctet,.number,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    linePosition = .log
                }
            case .destObjectService:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet,.number:
                    reportError()
                    return nil
                case .name(let objectName):
                    guard let destServiceObject = aclDelegate?.getObjectGroupService(objectName) else {
                        reportError()
                        return nil
                    }
                    self.destPort = destServiceObject.portRanges
                    linePosition = .lastDestPort
                }
            case .comment:
                linePosition = .comment
            case .log:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.fourOctet,.log:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .number(let logLevel):
                    guard logLevel <= 7 else {
                        reportError()
                        return
                    }
                case .name(let logName):
                    switch logName {
                    case "default","debug","debugging","informational","notification","warning","error","critical","alarm","emergency":
                        linePosition = .end
                    case "interval":
                        linePosition = .logInterval
                    default:
                        reportError()
                        return nil
                    }
                }
            case .logInterval:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.comment,.log,.fourOctet,.name:
                    reportError()
                    return nil
                case .number(_):
                    linePosition = .end
                }
            case .end:
                switch token {
                case .unsupported(let keyword):
                    reportUnsupported(keyword: keyword)
                    return nil
                case .accessList,.extended,.action,.ipProtocol,.any,.any4,.any6,.host,.addressV6,.cidrV6,.objectGroup,.portOperator,.fourOctet,.number,.name:
                    reportError()
                    return nil
                case .comment:
                    linePosition = .comment
                case .log:
                    linePosition = .log
                }
            }//switch linePosition
        }//wordLoop
        if validateAsa() == false {
            errorDelegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
            errorDelegate?.report(severity: .error, message: "Unable to create valid ACE based on line", delegateWindow: delegateWindow)
            return nil
        }
    }//init ASA


    func analyze(socket: Socket) -> AclAction {
        // check source ip
        var sourceIpMatch = false
        for sourceIpRange in self.sourceIp {
            if socket.sourceIp >= sourceIpRange.minIp && socket.sourceIp <= sourceIpRange.maxIp && socket.ipVersion == sourceIpRange.ipVersion {
                sourceIpMatch = true
            }
        }
        var destIpMatch = false
        for destIpRange in self.destIp {
            if socket.destinationIp >= destIpRange.minIp && socket.destinationIp <= destIpRange.maxIp && socket.ipVersion == destIpRange.ipVersion {
                destIpMatch = true
            }
        }
        if sourceIpMatch == false || destIpMatch == false {
            return .neither
        }
        // check ip protocol
        var protocolMatch = false
        for ipProtocol in self.ipProtocols {
            if ipProtocol == 0 {
                protocolMatch = true
                // since ips already match and protocol is any this is a match
                return self.aclAction
            }
            if socket.ipProtocol == ipProtocol {
                protocolMatch = true
            }
        }
        if protocolMatch == false {
            return .neither
        }

        if socket.ipProtocol == 17 || socket.ipProtocol == 6, let socketSourcePort = socket.sourcePort, let socketDestPort = socket.destinationPort {
            var sourcePortMatch = false
            if self.sourcePort.count == 0 {
                sourcePortMatch = true
            }
            for aceSourcePort in self.sourcePort {
                if aceSourcePort.contains(ipProtocol: socket.ipProtocol, port: socketSourcePort) {
                    sourcePortMatch = true
                }
                /*if socketSourcePort >= aceSourcePort.minPort && socketSourcePort <= aceSourcePort.maxPort {
                    sourcePortMatch = true
                }*/
            }
            var destPortMatch = false
            if self.destPort.count == 0 {
                destPortMatch = true
            }
            for aceDestPort in self.destPort {
                if aceDestPort.contains(ipProtocol: socket.ipProtocol, port: socketDestPort) {
                    destPortMatch = true
                }
                /*if socketDestPort >= aceDestPort.minPort && socketDestPort <= aceDestPort.maxPort {
                    destPortMatch = true
                }*/
            }
            if sourcePortMatch == false || destPortMatch == false {
                return .neither
            }
        }
        // check established flag if tcp and if ace requires established
        if socket.ipProtocol == 6 {
            if self.established == true {
                guard socket.established == true else {
                    return .neither
                }
            }
        }
        // at this point the acl is a match so we obey the action
        return self.aclAction
    }
}

extension AccessControlEntry: CustomStringConvertible {
    var description: String {
        var sourcePortString = ""
        for sourcePort in self.sourcePort {
            sourcePortString = sourcePortString + sourcePort.description + " "
        }
        var destPortString = ""
        for destPort in self.destPort {
            destPortString = destPortString + destPort.description + " "
        }
        
        var returnString = "\(aclAction) \(ipProtocols) \(sourceIp) source ports \(sourcePortString) to \(destIp) dest ports \(destPortString)"
        if self.established {
            returnString.append(" established\n")
        } else {
            returnString.append("\n")
        }
        return returnString
    }
}


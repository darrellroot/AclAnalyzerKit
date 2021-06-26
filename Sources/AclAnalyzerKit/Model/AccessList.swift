//
//  AccessList.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

public class AccessList {
    
    let MAXIP = UInt(UInt32.max)
    let MAXPORT = UInt(UInt16.max)

    let sourceText: String
    var accessControlEntries: [AccessControlEntry] = []
    var deviceType: DeviceType
    var aclNames: Set<String> = []  // names of the access-lists
    //var delegate: ErrorDelegate?
    var objectGroupNetworks = [String:ObjectGroupNetwork]()
    var objectGroupProtocols = [String:ObjectGroupProtocol]()
    var objectGroupServices = [String:ObjectGroupService]()
    var hostnames = [String:UInt128]() // ASA example: "name 2.2.2.203 trust18"
    var warnings: Set<String> = [] // summary warnings each to be printed out once at end of processing
    var aclErrors: [AclError] = [] // Errors generated during acl creation, in ACL line # order
    
    var count: Int {
        return accessControlEntries.count
    }
    
    enum ConfigurationMode {
        case objectGroupNetwork
        case objectGroupService
        case asaObjectNetwork  // only moves into this mode for one subnet command
        case nxosObjectGroupAddress
        case nxosObjectGroupPort
        case objectGroupProtocol
        case accessListExtended
        case accessControlEntry  // default
    }
    
    //public init(sourceText: String, deviceType: DeviceType, delegate: ErrorDelegate?, delegateWindow: DelegateWindow?) {
    public init(sourceText: String, deviceType: DeviceType) {
        self.sourceText = sourceText.lowercased()
        //self.delegate = delegate
        self.deviceType = deviceType
        var linenum = 0
        var lastSequenceSeen: UInt = 0  // used for making sure sequence numbers increase in the acl, each time we change configuration mode we reset this
        var configurationMode: ConfigurationMode = .accessControlEntry
        var objectName: String? = nil  //non-nil if we are in object-group mode
        var asaNamesEnabled = false // set to true if we see names keyword

        lineLoop: for line in self.sourceText.components(separatedBy: NSCharacterSet.newlines).map({ $0.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines) }) {
            
            linenum = linenum + 1
            
            /*func reportError() {
                let aclError = AclError(linenum: linenum, line: line, message: "line invalid, not included in analysis")
                self.aclErrors.append(aclError)
                //delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                //delegate?.report(severity: .error, message: "line invalid, not included in analysis", line: linenum, delegateWindow: delegateWindow)
            }*/

            if line.isEmpty {
                continue lineLoop
            }
            
            let words = line.split{ $0.isWhitespace }.map{ String($0)}
            
            if self.deviceType == .ios && words[safe: 0] == "object-group" && words[safe: 1] == "service" {
                let aclError = AclError(linenum: linenum, line: line, severity: .error, message: "ACL Analyzer does not support service object-groups for IOSXE. ACL ANALYSIS WILL NOT BE COMPLETE. Email acl sample to feedback@networkmom.net if this is a major problem")
                self.aclErrors.append(aclError)
                //delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                //delegate?.report(severity: .error, message: "ACL Analyzer does not support service object-groups for IOSXE. ACL ANALYSIS WILL NOT BE COMPLETE. Email acl sample to feedback@networkmom.net if this is a major problem", line: linenum, delegateWindow: delegateWindow)
                continue lineLoop
            }
            
            if self.deviceType == .ios && words[safe: 0] == "object-group" && words[safe: 1] == "network", let objectNameTemp = words[safe: 2] {
                self.warnings.insert("Not all IOS versions support object-groups")
                if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                    self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                    configurationMode = .objectGroupNetwork
                    lastSequenceSeen = 0
                    objectName = objectNameTemp
                } else {
                    //reportError()
                    let aclError = AclError(linenum: linenum, line: line, severity: .error, message: "Duplicate object-group name \(objectNameTemp)")
                    self.aclErrors.append(aclError)
                    //delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                }
                continue lineLoop
            }

            if self.deviceType == .iosxrv6 && words[safe: 0] == "object-group" && words[safe: 1] == "network" && words[safe: 2] == "ipv6", let objectNameTemp = words[safe: 3]  {
                if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                    self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                    configurationMode = .objectGroupNetwork
                    lastSequenceSeen = 0
                    objectName = objectNameTemp
                } else {
                    //reportError()
                    let aclError = AclError(linenum: linenum, line: line, severity: .error, message: "Duplicate object-group name \(objectNameTemp)")
                    self.aclErrors.append(aclError)
                    //delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                }
                continue lineLoop
            }

            if self.deviceType == .iosxr && words[safe: 0] == "object-group" && words[safe: 1] == "network" && words[safe: 2] == "ipv4", let objectNameTemp = words[safe: 3]  {
                if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                    self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                    configurationMode = .objectGroupNetwork
                    lastSequenceSeen = 0
                    objectName = objectNameTemp
                } else {
                    //reportError()
                    let aclError = AclError(linenum: linenum, line: line, severity: .error, message: "Duplicate object-group name \(objectNameTemp)")
                    self.aclErrors.append(aclError)

                    //delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                }
                continue lineLoop
            }
            
            if (self.deviceType == .iosxr || self.deviceType == .iosxrv6) && words[safe: 0] == "object-group" && words[safe: 1] == "port", let objectNameTemp = words[safe: 2]  {
                if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                    self.objectGroupServices[objectNameTemp] = ObjectGroupService(type: .tcpAndUdp)
                    configurationMode = .objectGroupService
                    lastSequenceSeen = 0
                    objectName = objectNameTemp
                    continue lineLoop
                } else {
                    //delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    let aclError = AclError(linenum: linenum, line: line, severity: .error, message: "Duplicate object-group name \(objectNameTemp)")
                    self.aclErrors.append(aclError)

                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                }
            }
            
            if (self.deviceType == .iosxr || self.deviceType == .iosxrv6) && configurationMode == .objectGroupService, let objectName = objectName, let objectGroup = objectGroupServices[objectName], let possibleSequence = words[safe: 0] {
                var myWords = words
                if let _ = UInt(possibleSequence) {
                    myWords.removeFirst()
                }
                if let firstWord = myWords[safe: 0],let secondWord = myWords[safe: 1] {
                    switch firstWord {
                    case "description":
                        break
                    case "eq":
                        if let firstPort = UInt(secondWord) ?? secondWord.tcpPort(deviceType: .iosxr, delegate: delegate, delegateWindow: delegateWindow) ?? secondWord.udpPort(deviceType: .iosxr, delegate: delegate, delegateWindow: delegateWindow) , let portRange = PortRange(minPort: firstPort, maxPort: firstPort) {
                            objectGroup.portRanges.append(portRange)
                            continue lineLoop
                        }
                    case "lt":
                        if let firstPort = UInt(secondWord) ?? secondWord.tcpPort(deviceType: .iosxr, delegate: delegate, delegateWindow: delegateWindow) ?? secondWord.udpPort(deviceType: .iosxr, delegate: delegate, delegateWindow: delegateWindow), firstPort > 0, let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) {
                            objectGroup.portRanges.append(portRange)
                            continue lineLoop
                        }
                    case "gt":
                        if let firstPort = UInt(secondWord) ?? secondWord.tcpPort(deviceType: .iosxr, delegate: delegate, delegateWindow: delegateWindow) ?? secondWord.udpPort(deviceType: .iosxr, delegate: delegate, delegateWindow: delegateWindow), firstPort < MAXPORT, let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) {
                            objectGroup.portRanges.append(portRange)
                            continue lineLoop
                        }
                    case "range":
                        if let firstPort = UInt(secondWord), let thirdWord = myWords[safe: 2], let secondPort = UInt(thirdWord), firstPort < secondPort, firstPort <= MAXPORT, secondPort <= MAXPORT, let portRange = PortRange(minPort: firstPort, maxPort: secondPort) {
                            objectGroup.portRanges.append(portRange)
                            continue lineLoop
                        }//case range
                    case "object-group":
                        if let nestedObjectName = myWords[safe: 1], let nestedObject = objectGroupServices[nestedObjectName] {
                            objectGroup.portRanges.append(contentsOf: nestedObject.portRanges)
                            continue lineLoop
                        }//case object-group
                    default:
                        break
                    }//switch firstWord
                }//let firstWord
            }//if self.deviceType
            
            if deviceType == .asa && words[safe: 0] == "object" && words[safe: 1] ==
            "network", let tempObjectName = words[safe: 2] {
                objectName = tempObjectName
                configurationMode = .asaObjectNetwork
                continue lineLoop
            }
            
            if deviceType == .asa && configurationMode == .asaObjectNetwork && words[safe: 0] == "subnet", let possibleSubnet = words[safe: 1], let possibleNetmask = words[safe: 2], let objectName = objectName, let ipRange = IpRange(ip: possibleSubnet, netmask: possibleNetmask) {
                let objectGroupNetwork = ObjectGroupNetwork()
                objectGroupNetwork.append(ipRange: ipRange)
                objectGroupNetworks[objectName] = objectGroupNetwork
                configurationMode = .accessControlEntry
                continue lineLoop
            }
            
            if deviceType == .asa && configurationMode == .asaObjectNetwork && words[safe: 0] == "subnet", let possibleSubnet = words[safe: 1], let objectName = objectName, let ipRange = IpRange(cidr: possibleSubnet), ipRange.ipVersion == .IPv6 {
                let objectGroupNetwork = ObjectGroupNetwork()
                objectGroupNetwork.append(ipRange: ipRange)
                objectGroupNetworks[objectName] = objectGroupNetwork
                configurationMode = .accessControlEntry
                continue lineLoop
            }
            
            if deviceType == .asa && configurationMode == .asaObjectNetwork && words[safe: 0] == "host", let possibleIp = words[safe: 1], let objectName = objectName, let ip = possibleIp.ipv4address {
                let ipRange = IpRange(minIp: ip, maxIp: ip, ipVersion: .IPv4)
                let objectGroupNetwork = ObjectGroupNetwork()
                objectGroupNetwork.append(ipRange: ipRange)
                objectGroupNetworks[objectName] = objectGroupNetwork
                configurationMode = .accessControlEntry
                continue lineLoop
            }
            
            if deviceType == .asa && configurationMode == .asaObjectNetwork && words[safe: 0] == "host", let possibleIp = words[safe: 1], let objectName = objectName, let ip = possibleIp.ipv6address {
                let ipRange = IpRange(minIp: ip, maxIp: ip, ipVersion: .IPv6)
                let objectGroupNetwork = ObjectGroupNetwork()
                objectGroupNetwork.append(ipRange: ipRange)
                objectGroupNetworks[objectName] = objectGroupNetwork
                configurationMode = .accessControlEntry
                continue lineLoop
            }
            
            if deviceType == .asa && configurationMode == .asaObjectNetwork && words[safe: 0] == "range", let firstIpString = words[safe: 1], let firstIp = firstIpString.ipv4address, let secondIpString = words[safe: 2], let secondIp = secondIpString.ipv4address, firstIp <= secondIp, let objectName = objectName {
                let ipRange = IpRange(minIp: firstIp, maxIp: secondIp, ipVersion: .IPv4)
                let objectGroupNetwork = ObjectGroupNetwork()
                objectGroupNetwork.append(ipRange: ipRange)
                objectGroupNetworks[objectName] = objectGroupNetwork
                configurationMode = .accessControlEntry
                continue lineLoop
            }
            
            if deviceType == .asa && configurationMode == .asaObjectNetwork && words[safe: 0] == "range", let firstIpString = words[safe: 1], let firstIp = firstIpString.ipv6address, let secondIpString = words[safe: 2], let secondIp = secondIpString.ipv6address, firstIp <= secondIp, let objectName = objectName {
                let ipRange = IpRange(minIp: firstIp, maxIp: secondIp, ipVersion: .IPv6)
                let objectGroupNetwork = ObjectGroupNetwork()
                objectGroupNetwork.append(ipRange: ipRange)
                objectGroupNetworks[objectName] = objectGroupNetwork
                configurationMode = .accessControlEntry
                continue lineLoop
            }

            if deviceType == .asa && words[safe: 0] == "object-group" && words[safe: 1] == "network" {
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                        configurationMode = .objectGroupNetwork
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                   } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if deviceType == .nxosv6 && words[safe: 0] == "object-group" && words[safe: 1] == "ipv6" && words[safe: 2] == "address" , let objectNameTemp = words[safe: 3] {
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                    delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                    continue lineLoop
                }
                self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                configurationMode = .nxosObjectGroupAddress
                lastSequenceSeen = 0
                objectName = objectNameTemp
                continue lineLoop
            }

            if deviceType == .nxos && words[safe: 0] == "object-group" && words[safe: 1] == "ip" && words[safe: 2] == "address" , let objectNameTemp = words[safe: 3] {
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group name \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                        continue lineLoop
                }
                self.objectGroupNetworks[objectNameTemp] = ObjectGroupNetwork()
                configurationMode = .nxosObjectGroupAddress
                lastSequenceSeen = 0
                objectName = objectNameTemp
                continue lineLoop
            }
            
            if (deviceType == .nxos || deviceType == .nxosv6) && words[safe: 0] == "object-group" && words[safe: 1] == "ip" && words[safe: 2] == "port", let objectNameTemp = words[safe: 3] {
                guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                    configurationMode = .accessControlEntry
                    lastSequenceSeen = 0
                    objectName = nil
                    continue lineLoop
                }
                let objectGroupService = ObjectGroupService(type: .tcpAndUdp)
                self.objectGroupServices[objectNameTemp] = objectGroupService
                configurationMode = .nxosObjectGroupPort
                lastSequenceSeen = 0
                objectName = objectNameTemp
                continue lineLoop
            }
            
            if (deviceType == .iosxr || deviceType == .ios) && configurationMode == .objectGroupNetwork, let objectName = objectName, let objectGroup = objectGroupNetworks[objectName] {
                if words[safe: 0] == "description" {
                    continue lineLoop
                }
                if words[safe: 0] == "host" {
                    guard let ipString = words[safe:1], let ipAddress = ipString.ipv4address else {
                        
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "", line: linenum, delegateWindow: delegateWindow)
                        continue lineLoop
                    }
                    let hostIpRange = IpRange(minIp: ipAddress, maxIp: ipAddress, ipVersion: .IPv4)
                    objectGroup.append(ipRange: hostIpRange)
                    continue lineLoop
                }
                
                //range x.x.x.x x.x.x.y only applied to IOS-XR
                if deviceType == .iosxr && words[safe: 0] == "range", let firstIpString = words[safe: 1], let firstIp = firstIpString.ipv4address, let secondIpString = words[safe: 2], let secondIp = secondIpString.ipv4address, firstIp <= secondIp {
                    let ipRange = IpRange(minIp: firstIp, maxIp: secondIp, ipVersion: .IPv4)
                    objectGroup.append(ipRange: ipRange)
                    continue lineLoop
                }
                if let possibleIpString = words[safe: 0], let possibleNetmaskString = words[safe: 1], let ipRange = IpRange(ip: possibleIpString, netmask: possibleNetmaskString) {
                    if ipRange.bitAligned == false {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .warning, message: "Not aligned on bit boundary", line: linenum, delegateWindow: delegateWindow)
                    }
                    objectGroup.append(ipRange: ipRange)
                    continue lineLoop
                }
                if deviceType == .iosxr && words[safe: 0] == "object-group", let possibleObjectName = words[safe: 1], let nestedObjectGroup = self.objectGroupNetworks[possibleObjectName] {
                    objectGroup.ipRanges.append(contentsOf: nestedObjectGroup.ipRanges)
                    continue lineLoop
                }
                if deviceType == .ios && words[safe: 0] == "group-object", let possibleObjectName = words[safe: 1], let nestedObjectGroup = self.objectGroupNetworks[possibleObjectName] {
                    objectGroup.ipRanges.append(contentsOf: nestedObjectGroup.ipRanges)
                    continue lineLoop
                }
            }
            
            if deviceType == .iosxrv6 && configurationMode == .objectGroupNetwork, let objectName = objectName, let objectGroup = objectGroupNetworks[objectName] {
                if words[safe: 0] == "description" {
                    continue lineLoop
                }
                if words[safe: 0] == "host" {
                    guard let ipString = words[safe:1], let ipAddress = ipString.ipv6address else {
                        
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "", line: linenum, delegateWindow: delegateWindow)
                        continue lineLoop
                    }
                    let hostIpRange = IpRange(minIp: ipAddress, maxIp: ipAddress, ipVersion: .IPv6)
                    objectGroup.append(ipRange: hostIpRange)
                    continue lineLoop
                }
                
                //range x.x.x.x x.x.x.y only applied to IOS-XR
                if deviceType == .iosxrv6 && words[safe: 0] == "range", let firstIpString = words[safe: 1], let firstIp = firstIpString.ipv6address, let secondIpString = words[safe: 2], let secondIp = secondIpString.ipv6address, firstIp <= secondIp {
                    let ipRange = IpRange(minIp: firstIp, maxIp: secondIp, ipVersion: .IPv6)
                    objectGroup.append(ipRange: ipRange)
                    continue lineLoop
                }
                if let possibleCidr = words[safe: 0], let ipRange = IpRange(cidr: possibleCidr) {
                    if ipRange.bitAligned == false {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .warning, message: "Not aligned on bit boundary", line: linenum, delegateWindow: delegateWindow)
                    }
                    objectGroup.append(ipRange: ipRange)
                    continue lineLoop
                }
                if deviceType == .iosxrv6 && words[safe: 0] == "object-group", let possibleObjectName = words[safe: 1], let nestedObjectGroup = self.objectGroupNetworks[possibleObjectName] {
                    objectGroup.ipRanges.append(contentsOf: nestedObjectGroup.ipRanges)
                    continue lineLoop
                }
            }

            if (deviceType == .nxos || deviceType == .nxosv6) && configurationMode == .nxosObjectGroupPort {
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces)
                // first word could be sequence number
                var localwords: [String]
                if let firstWord = words.first, let thisSequence = UInt(firstWord) {
                    localwords = Array(words.dropFirst())
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                } else {
                    localwords = words
                }

                if let localword = localwords.first, let token = NxAclToken(string: localword), let currentObjectName = objectName, let currentObjectGroup = objectGroupServices[currentObjectName] {
                    switch token {
                    case .action(_), .ipProtocol, .any, .host, .comment, .log, .addrgroup,.portgroup,.established, .fourOctet, .cidr, .number, .name,.unsupported:
                        break
                        //do nothing and proceed to ACE analysis
                    case .portOperator(let portOperator):
                        guard let firstPortString = localwords[safe: 1], let firstPort = UInt(firstPortString) ?? firstPortString.tcpPort(deviceType: .nxos, delegate: delegate, delegateWindow: delegateWindow) ?? firstPortString.udpPort(deviceType: .nxos, delegate: delegate, delegateWindow: delegateWindow), firstPort >= 0, firstPort <= MAXPORT else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                        switch portOperator {
                        case .eq:
                            if let portRange = PortRange(minPort: firstPort, maxPort: firstPort) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        case .gt:
                            if let portRange = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        case .lt:
                            if let portRange = PortRange(minPort: 0, maxPort: firstPort - 1) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        case .ne:
                            if let portRange1 = PortRange(minPort: 0, maxPort: firstPort - 1) {
                                currentObjectGroup.append(portRange: portRange1)
                            }
                            if let portRange2 = PortRange(minPort: firstPort + 1, maxPort: MAXPORT) {
                                currentObjectGroup.append(portRange: portRange2)
                            }
                            continue lineLoop
                        case .range:
                            if let secondPortString = localwords[safe: 2], let secondPort = UInt(secondPortString) ?? secondPortString.tcpPort(deviceType: .nxos, delegate: delegate, delegateWindow: delegateWindow) ?? secondPortString.udpPort(deviceType: .nxos, delegate: delegate, delegateWindow: delegateWindow), secondPort >= 0, secondPort <= MAXPORT, let portRange = PortRange(minPort: firstPort, maxPort: secondPort) {
                                currentObjectGroup.append(portRange: portRange)
                                continue lineLoop
                            } else {
                                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                                delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                                continue lineLoop
                            }
                        }
                    }
                }
            }
            
            if deviceType == .nxosv6 && configurationMode == .nxosObjectGroupAddress {
                // first word could be sequence number, drop it and process the rest
                var localwords = words
                if let firstword = localwords[safe: 0], let thisSequence = UInt(firstword) {
                    localwords.removeFirst()
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                }
                if let word1 = localwords.first, let token = NxAclTokenV6(string: word1), let currentObjectName = objectName, let currentObjectGroup = objectGroupNetworks[currentObjectName] {
                    
                    switch token {
                        
                    case .action(_),.ipProtocol, .any, .portOperator, .comment, .log, .addrgroup,.portgroup,.established, .number, .name, .unsupported,.addressV6:
                        break
                    //do nothing and continue, we might be done with object group
                    case .host:
                        guard let word2 = localwords[safe: 1], let token2 = NxAclTokenV6(string: word2), case let .addressV6(hostIp) = token2 else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            lastSequenceSeen = 0
                            objectName = nil
                            continue lineLoop
                        }
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp, ipVersion: .IPv6)
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop
/*                    case .addressV6(let network):
                        guard let word2 = localwords[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(mask) = token2, mask >= 0, mask <= MAXIP, let ipRange = IpRange(ipv4: network, dontCare: mask) else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            lastSequenceSeen = 0
                            objectName = nil
                            continue lineLoop
                        }
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop*/
                    case .cidrV6(let cidr):
                        currentObjectGroup.append(ipRange: cidr)
                        continue lineLoop
                    }
                }
            }

            if deviceType == .nxos && configurationMode == .nxosObjectGroupAddress {
                // first word could be sequence number, drop it and process the rest
                var localwords = words
                if let firstword = localwords[safe: 0], let thisSequence = UInt(firstword) {
                    localwords.removeFirst()
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                }
                if let word1 = localwords.first, let token = NxAclToken(string: word1), let currentObjectName = objectName, let currentObjectGroup = objectGroupNetworks[currentObjectName] {
                
                    switch token {
                        
                    case .action(_),.ipProtocol, .any, .portOperator, .comment, .log, .addrgroup,.portgroup,.established, .number, .name, .unsupported:
                        break
                        //do nothing and continue, we might be done with object group
                    case .host:
                        guard let word2 = localwords[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(hostIp) = token2, hostIp >= 0, hostIp <= MAXIP else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            lastSequenceSeen = 0
                            objectName = nil
                            continue lineLoop
                        }
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp, ipVersion: .IPv4)
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop
                    case .fourOctet(let network):
                        guard let word2 = localwords[safe: 1], let token2 = NxAclToken(string: word2), case let .fourOctet(mask) = token2, mask >= 0, mask <= MAXIP, let ipRange = IpRange(ipv4: network, dontCare: mask) else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "Error decoding nxos object-group", line: linenum, delegateWindow: delegateWindow)
                            configurationMode = .accessControlEntry
                            lastSequenceSeen = 0
                            objectName = nil
                            continue lineLoop
                        }
                        currentObjectGroup.append(ipRange: ipRange)
                        continue lineLoop
                    case .cidr(let cidr):
                        currentObjectGroup.append(ipRange: cidr)
                        continue lineLoop
                    }
                }
            }
            
            //if line.starts(with: "object-group service") {
            if deviceType == .asa && words[safe: 0] == "object-group" && words[safe: 1] == "service" {
                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                delegate?.report(severity: .error, message: "object-group service not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                continue lineLoop
            }/*
                if let objectNameTemp = words[safe: 2] {
                    guard self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil else {
                        delegate?.report(severity: .error, message: "Duplicate object-group service \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                        continue lineLoop
                    }
                    let type = words[safe: 3]
                    switch type {
                    case .none:
                        let objectGroupService = ObjectGroupService(type: .none)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        continue lineLoop
                    case .some("tcp"):
                        let objectGroupService = ObjectGroupService(type: .tcp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        self.warnings.insert("Cisco deprecated tcp/udp/tcp-udp in object-group service")
                        continue lineLoop
                    case .some("udp"):
                        let objectGroupService = ObjectGroupService(type: .udp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        self.warnings.insert("Cisco deprecated tcp/udp/tcp-udp in object-group service")
                        continue lineLoop
                    case .some("tcp-udp"):
                        let objectGroupService = ObjectGroupService(type: .tcpAndUdp)
                        self.objectGroupServices[objectNameTemp] = objectGroupService
                        configurationMode = .objectGroupService
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                        self.warnings.insert("Cisco deprecated tcp/udp/tcp-udp in object-group service")
                        continue lineLoop
                    default:
                        delegate?.report(severity: .error, message: "Invalid object-group type \(type)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                        continue lineLoop
                    }
                }
                continue lineLoop //should not get here but just in case
            }*/
            
            if deviceType == .asa && words[safe: 0] == "names" {
                asaNamesEnabled = true
                continue lineLoop
            }
            
            if words[safe: 0] == "object-group" && words[safe: 1] == "protocol" {
            //if line.starts(with: "object-group protocol") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group protocol not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                //let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let objectNameTemp = words[safe: 2] {
                    if self.objectGroupNetworks[objectNameTemp] == nil  && self.objectGroupServices[objectNameTemp] == nil && self.objectGroupProtocols[objectNameTemp] == nil {
                        self.objectGroupProtocols[objectNameTemp] = ObjectGroupProtocol()
                        configurationMode = .objectGroupProtocol
                        lastSequenceSeen = 0
                        objectName = objectNameTemp
                    } else {
                        delegate?.report(severity: .error, message: "Duplicate object-group protocol \(objectNameTemp)", line: linenum, delegateWindow: delegateWindow)
                        configurationMode = .accessControlEntry
                        lastSequenceSeen = 0
                        objectName = nil
                    }
                }
                continue lineLoop
            }
            
            if line.starts(with: "group-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                switch configurationMode {
                    
                case .objectGroupNetwork:
                    if let currentObjectName = objectName, let currentObjectGroup = objectGroupNetworks[currentObjectName], let nestedObjectName = words[safe: 1], let nestedObjectGroup = objectGroupNetworks[nestedObjectName] {
                        currentObjectGroup.ipRanges.append(contentsOf: nestedObjectGroup.ipRanges)
                        continue lineLoop
                    }
                case .objectGroupProtocol:
                    if let currentObjectName = objectName, let currentObjectGroup = objectGroupProtocols[currentObjectName], let nestedObjectName = words[safe: 1], let nestedObjectGroup = objectGroupProtocols[nestedObjectName] {
                        currentObjectGroup.ipProtocols.append(contentsOf: nestedObjectGroup.ipProtocols)
                        continue lineLoop
                    }
                case .objectGroupService:
                    if let currentObjectName = objectName, let currentObjectGroup = objectGroupServices[currentObjectName], let nestedObjectName = words[safe: 1], let nestedObjectGroup = objectGroupServices[nestedObjectName] {
                        if currentObjectGroup.type == nestedObjectGroup.type {
                            currentObjectGroup.portRanges.append(contentsOf: nestedObjectGroup.portRanges)
                        } else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "nested service object-groups must be the same type", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                        continue lineLoop
                    }
                case .accessListExtended, .accessControlEntry, .nxosObjectGroupPort, .nxosObjectGroupAddress, .asaObjectNetwork:
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "unexpected group-object", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
            }
            if words[safe: 0] == "protocol-object" {
            //if line.starts(with: "protocol-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if configurationMode != .objectGroupProtocol {
                    delegate?.report(severity: .error, message: "Unexpected protocol-object", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                if let term1 = words[safe: 1], let objectName = objectName {
                    // get protocol number
                    var ipProtocol: UInt? = nil
                    if let protocolNumber = UInt(term1) {
                        if protocolNumber < 256 {
                            ipProtocol = protocolNumber
                        } else {
                            delegate?.report(severity: .error, message: "IP protocol must be between 0 and 255 inclusive", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                    } else {
                        if let protocolNumber = term1.ipProtocol(deviceType: .asa, delegate: delegate, delegateWindow: delegateWindow) {
                            ipProtocol = protocolNumber
                        } else {
                            delegate?.report(severity: .error, message: "Unable to identify IP protocol", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                    }
                    if let ipProtocol = ipProtocol, let objectGroupProtocol = objectGroupProtocols[objectName] {
                        objectGroupProtocol.append(ipProtocol: ipProtocol)
                    }
                } else {
                    delegate?.report(severity: .error, message: "Unable to identify IP protocol", line: linenum, delegateWindow: delegateWindow)
                }
                continue lineLoop
            }
            
            if deviceType == .asa && asaNamesEnabled == true && words[safe: 0] == "name", let ipString = words[safe: 1], let nameString = words[safe: 2], let ipAddress = ipString.ipv4address {
                guard hostnames[nameString] == nil else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "name \(nameString) duplicates prior name", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                guard ipAddress <= UInt.MAXIPV4 else {
                    //should not get here
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "unexpected host ip address value calculated \(ipAddress) please send data to feedback@networkmom.net", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                hostnames[nameString] = ipAddress
                continue lineLoop
            }
            
            if deviceType == .asa && asaNamesEnabled == false && words[safe: 0] == "name" && words.count >= 3 {
                delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                delegate?.report(severity: .error, message: "ASA name command requires prior names command", line: linenum, delegateWindow: delegateWindow)
                continue lineLoop
            }
            
            // has to be after object-group network xxxxxx
            // handling 2-word cases like this:
            // network-object host 2001:DB8::0DB8:800:200C:417A
            if deviceType == .asa && configurationMode == .objectGroupNetwork && words.count == 2 && words[safe: 0] == "network-object", let term1String = words[safe: 1], let objectName = objectName, let objectGroupNetwork = objectGroupNetworks[objectName], let ipRange = IpRange(cidr: term1String), ipRange.ipVersion == .IPv6 {
                objectGroupNetwork.append(ipRange: ipRange)
                continue lineLoop
            }
            // has to be after object-group network xxxxxx
            // handling cases like this:
            //  network-object host AZ4-vTEST
            //  network-object host 131.252.209.18
            //  network-object Net-CorpOne1 255.255.255.252
            //  network-object 131.252.209.0 255.255.255.0
            //
            // This case only handles 3-word cases
            if deviceType == .asa && configurationMode == .objectGroupNetwork && words.count == 3 && words[safe: 0] == "network-object", let term1String = words[safe: 1], let term2String = words[safe: 2], let objectName = objectName, let objectGroupNetwork = objectGroupNetworks[objectName] {
                if term1String == "host" {
                    //network-object host 131.252.209.18
                    if let hostIp = term2String.ipv4address {
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp, ipVersion: .IPv4)
                        objectGroupNetwork.append(ipRange: ipRange)
                        continue lineLoop
                    } else if let hostIp = term2String.ipv6address {
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp, ipVersion: .IPv6)
                        objectGroupNetwork.append(ipRange: ipRange)
                        continue lineLoop
                    } else if let hostIp = hostnames[term2String] {
                        // network-object host AZ4-vTEST
                        guard hostIp < UInt.MAXIPV4 else {
                            // should not get here
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "unexpected error decoding host ip", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                        let ipRange = IpRange(minIp: hostIp, maxIp: hostIp, ipVersion: .IPv4)
                        objectGroupNetwork.append(ipRange: ipRange)
                        continue lineLoop
                    } else {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "unable to decode network-object", line: linenum, delegateWindow: delegateWindow)
                        continue lineLoop
                    }
                } else {
                    //  network-object Net-CorpOne1 255.255.255.252
                    //  network-object 131.252.209.0 255.255.255.0
                    if let subnet = term1String.ipv4address {
                        //  network-object 131.252.209.0 255.255.255.0
                        guard let ipRange = IpRange(ip: subnet, netmask: term2String) else {
                            delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                            delegate?.report(severity: .error, message: "unable to decode network-object", line: linenum, delegateWindow: delegateWindow)
                            continue lineLoop
                        }
                        objectGroupNetwork.append(ipRange: ipRange)
                        continue lineLoop
                    } else {
                        //  network-object Net-CorpOne1 255.255.255.252
                        // our object group should have 1 element which must be /32
                        guard let subnet = hostnames[term1String], let ipRange = IpRange(ip: subnet, netmask: term2String) else {
                            continue lineLoop
                        }
                        objectGroupNetwork.append(ipRange: ipRange)
                        continue lineLoop
                    }
                }
            }
            if deviceType == .iosv6 && words[safe: 0] == "ipv6" && words[safe: 1] == "access-list" {
                //if line.starts(with: "ipv6 access-list ") {
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let aclName = words[safe: 2] {
                    aclNames.insert(aclName)
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }

            if deviceType == .ios && words[safe: 0] == "ip" && words[safe: 1] == "access-list" && words[safe: 2] == "extended" {
            //if line.starts(with: "ip access-list extended") {
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let aclName = words[safe: 3] {
                    aclNames.insert(aclName)
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            
            
            if deviceType == .nxos && words[safe: 0] == "ip" && words[safe: 1] == "access-list" {
            //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    aclNames.insert(String(aclName))
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            
            if deviceType == .arista && words[safe: 0] == "ip" && words[safe: 1] == "access-list" {
            //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    aclNames.insert(String(aclName))
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            
            if deviceType == .nxosv6 && words[safe: 0] == "ipv6" && words[safe: 1] == "access-list" {
                //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    aclNames.insert(String(aclName))
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            
            if deviceType == .aristav6 && words[safe: 0] == "ipv6" && words[safe: 1] == "access-list" {
                //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    aclNames.insert(String(aclName))
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }

            if deviceType == .iosxrv6 && words[safe: 0] == "ipv6" && words[safe: 1] == "access-list" {
                //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    aclNames.insert(String(aclName))
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }

            if deviceType == .iosxr && words[safe: 0] == "ipv4" && words[safe: 1] == "access-list" {
                //if line.starts(with: "ip access-list") {  // ip access-list extended case already covered
                objectName = nil
                configurationMode = .accessListExtended
                lastSequenceSeen = 0
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                if let aclName = words[safe: 2] {
                    aclNames.insert(String(aclName))
                    if aclNames.count > 1 {
                        self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
                    }
                }
                continue lineLoop
            }
            
            if words[safe: 0] == "statistics" && words[safe: 1] == "per-entry" {
            //if line.starts(with: "statistics per-entry") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "statistics per entry not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                continue lineLoop
            }
            if words[safe: 0] == "fragments" && (words[safe: 1] == "permit-all" || words[safe: 1] == "deny-all") {
            //if line.starts(with: "fragments permit-all") || line.starts(with: "fragments deny-all") {
                guard deviceType == .nxos else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "statistics per entry not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                delegate?.report(severity: .warning, message: "Fragments line not considered in ACL analysis", line: linenum, delegateWindow: delegateWindow)
                continue lineLoop
            }

            if words[safe: 0] == "description" {
            //if line.starts(with: "description") {
                if configurationMode == .objectGroupNetwork || configurationMode == .objectGroupService || configurationMode == .objectGroupProtocol {
                    continue lineLoop
                } else {
                    delegate?.report(severity: .linetext, message: "\(line)", line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .warning, message: "Unexpected description", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
            }
            if words[safe: 0] == "port-object" {
            //if line.starts(with: "port-object") {
                guard deviceType == .asa else {
                    delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                    delegate?.report(severity: .error, message: "object-group not supported for device type \(deviceType)", line: linenum, delegateWindow: delegateWindow)
                    continue lineLoop
                }
                let words = line.split{ $0.isWhitespace }.map{ String($0)}
                //let words = line.components(separatedBy: NSCharacterSet.whitespaces).filter { !$0.isEmpty }
                if let portOperator = words[safe: 1] {
                    switch portOperator {
                    case "eq":
                        if let portNumber = words[safe: 2]?.asaPort, let portRange = PortRange(minPort: portNumber, maxPort: portNumber), let objectName = objectName, let objectGroup = objectGroupServices[objectName] {
                            objectGroup.append(portRange: portRange)
                            continue lineLoop
                        } else {
                            continue lineLoop
                        }
                    case "range":
                        if let lowPort = words[safe: 2]?.asaPort, let highPort = words[safe: 3]?.asaPort, let portRange = PortRange(minPort: lowPort, maxPort: highPort), let objectName = objectName, let objectGroup = objectGroupServices[objectName] {
                            objectGroup.append(portRange: portRange)
                            continue lineLoop
                        } else {
                            continue lineLoop
                        }
                    default: // switch portOperator
                        continue lineLoop
                    }
                } else { // if let portOperator else
                    continue lineLoop
                }
            }
            
            //debugPrint("starting timer")
            let timer = Timer(timeInterval: 1.0, repeats: false) { timer in
                //debugPrint("timer fired")
                self.delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                self.delegate?.report(severity: .error, message: "line took more than 1 second to parse, please email this line to feedback@networkmom.net", line: linenum, delegateWindow: delegateWindow)
            }
            RunLoop.main.add(timer, forMode: .common)
            
            if let accessControlEntry = AccessControlEntry(line: line, deviceType: deviceType, linenum: linenum, aclDelegate: self, errorDelegate: delegate, delegateWindow: delegateWindow) {
                objectName = nil
                configurationMode = .accessControlEntry
                accessControlEntries.append(accessControlEntry)
                if let thisSequence = accessControlEntry.sequence {
                    if thisSequence <= lastSequenceSeen {
                        delegate?.report(severity: .linetext, message: line, line: linenum, delegateWindow: delegateWindow)
                        delegate?.report(severity: .error, message: "Sequence number not increasing.  ACL analysis will not be accurate!", line: linenum, delegateWindow: delegateWindow)
                    }
                    lastSequenceSeen = thisSequence
                }
            }
            timer.invalidate()
        }
    }
    /*public func analyze(socket: Socket) -> AclAction {
        let (action, _) = analyze(socket: socket)
        return action
    }*/
    public func analyze(socket: Socket) -> (AclAction, String) {
        var aclAction: AclAction? = nil
        var messages = ""
        for accessControlEntry in accessControlEntries {
            let aceAction = accessControlEntry.analyze(socket: socket)
            switch aceAction {
            case .neither:
                continue
            case .permit, .deny:
                if aclAction == nil {
                    // first match in acl
                    aclAction = aceAction
                    messages.append("FIRST MATCH \(accessControlEntry.line)\n")
                    //errorDelegate?.report(severity: .result, message: "FIRST MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum, delegateWindow: delegateWindow)
                } else {
                    // later match in acl
                    messages.append("ALSO MATCH \(accessControlEntry.line)\n")
                    //errorDelegate?.report(severity: .result, message: "ALSO MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum, delegateWindow: delegateWindow)
                }
            }
        }
        guard let finalAclAction = aclAction else {
            // no match found, implicit deny
            messages.append("No Match Found, implicit \(AclAction.deny)\n")
            //delegate?.report(severity: .result, message: "No Match Found, implicit \(AclAction.deny)", delegateWindow: delegateWindow)
            return (.deny,messages)
        }
        return (finalAclAction,messages)
    }

    //func analyze(socket: Socket, errorDelegate: ErrorDelegate? = nil, delegateWindow: DelegateWindow? = nil) -> AclAction {
    /*func analyze(socket: Socket, errorDelegate: ErrorDelegate?, delegateWindow: DelegateWindow?) -> AclAction {
        var aclAction: AclAction? = nil
        for accessControlEntry in accessControlEntries {
            let aceAction = accessControlEntry.analyze(socket: socket)
            switch aceAction {
            case .neither:
                continue
            case .permit, .deny:
                if aclAction == nil {
                    // first match in acl
                    aclAction = aceAction
                    errorDelegate?.report(severity: .result, message: "FIRST MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum, delegateWindow: delegateWindow)
                } else {
                    // later match in acl
                    errorDelegate?.report(severity: .result, message: "ALSO MATCH \(accessControlEntry.line)", line: accessControlEntry.linenum, delegateWindow: delegateWindow)
                }
            }
        }
        guard let finalAclAction = aclAction else {
            // no match found, implicit deny
            delegate?.report(severity: .result, message: "No Match Found, implicit \(AclAction.deny)", delegateWindow: delegateWindow)
            return .deny
        }
        return finalAclAction
    }*/
}
extension AccessList: AclDelegate {
    func getHostname(_ hostname: String) -> UInt128? {
        return self.hostnames[hostname]
    }
    
    func getObjectGroupNetwork(_ group: String) -> ObjectGroupNetwork? {
        if let objectGroupNetwork = self.objectGroupNetworks[group] {
            return objectGroupNetwork
        } else {
            return nil
        }
    }
    func getObjectGroupService(_ group: String) -> ObjectGroupService? {
        if let objectGroupService = self.objectGroupServices[group] {
            return objectGroupService
        } else {
            return nil
        }
    }
    func getObjectGroupProtocol(_ group: String) -> ObjectGroupProtocol? {
        if let objectGroupProtocol = self.objectGroupProtocols[group] {
            return objectGroupProtocol
        } else {
            return nil
        }
    }

    func foundName(_ name: String, delegateWindow: DelegateWindow? = nil) {
        aclNames.insert(name)
        if aclNames.count > 1 {
            self.delegate?.report(severity: .error, message: "ACL has inconsistent names: \(aclNames) found", delegateWindow: delegateWindow)
        }
    }
}


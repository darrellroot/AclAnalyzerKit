//
//  RandomAcl.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/24/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct RandomAcl: CustomStringConvertible {
    static var staticSequence: Int = 1
    var sequence: Int
    var myDescription: String
    
    static let protocols = ["ip","tcp","udp","6","17","gre"]
    static let protocolsv6 = ["ipv6","tcp","udp","6","17","ahp"]
    static let protocolsArista = ["ahp","igmp","ip","ospf","pim","tcp","udp","vrrp"]
    static let protocolsAristaV6 = ["icmpv6","ipv6","ospf","tcp","udp"]
    
    init(deviceType: DeviceType) {
                
        self.sequence = RandomAcl.staticSequence
        if deviceType == .iosxr || deviceType == .iosxrv6 {
            RandomAcl.staticSequence = RandomAcl.staticSequence + 1
        }
        
        let sourceString, destString: String
        var ipProtocol: String

        switch deviceType {
        case .ios,.iosxr:
            ipProtocol = RandomAcl.protocols.randomElement()!
        case .asa:
            ipProtocol = RandomAcl.protocols.randomElement()!  // will get rewritten for ipv6
        case .nxos:
            ipProtocol = RandomAcl.protocols.randomElement()!
        case .arista:
            ipProtocol = RandomAcl.protocolsArista.randomElement()!
        case .iosv6,.nxosv6,.iosxrv6:
            ipProtocol = RandomAcl.protocolsv6.randomElement()!
        case .aristav6:
            ipProtocol = RandomAcl.protocolsAristaV6.randomElement()!
        }
        switch deviceType {
        
        case .ios,.iosxr:
            var sourceIp = UInt.random(in: 0...UInt(UInt32.max))
            let sourcePrefix = Ipv4Prefix.allCases.randomElement()!
            let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
            sourceIp = sourceIp - sourceRemainder
            
            var destIp = UInt.random(in: 0...UInt(UInt32.max))
            let destPrefix = Ipv4Prefix.allCases.randomElement()!
            let destRemainder = destIp % destPrefix.dontCareHosts
            destIp = destIp - destRemainder
            
            sourceString = "\(sourceIp.ipv4) \(sourcePrefix.dontCareBits) "
            destString = " \(destIp.ipv4) \(destPrefix.dontCareBits) "

        case .asa:
            let ipVersion = IpVersion.allCases.randomElement()!
            
            switch ipVersion {
            case .IPv4:
                var sourceIp = UInt.random(in: 0...UInt(UInt32.max))
                let sourcePrefix = Ipv4Prefix.allCases.randomElement()!
                let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
                sourceIp = sourceIp - sourceRemainder
                
                var destIp = UInt.random(in: 0...UInt(UInt32.max))
                let destPrefix = Ipv4Prefix.allCases.randomElement()!
                let destRemainder = destIp % destPrefix.dontCareHosts
                destIp = destIp - destRemainder
                
                sourceString = "\(sourceIp.ipv4) \(sourcePrefix.netmask) "
                destString = " \(destIp.ipv4) \(destPrefix.netmask) "
                //ipProtocol = RandomAcl.protocols.randomElement()!  // rewriting
            case .IPv6:
                let sourceV6 = UInt128.random(in: 0...UInt128.max)
                let sourceV6Prefix = UInt.random(in: 0...128)
                let sourceV6String = "\(sourceV6.ipv6)/\(sourceV6Prefix)"
                let sourceV6cidr = Cidr(cidr: sourceV6String)!  //TODO get rid of !
                sourceString = "\(sourceV6cidr) "
                
                let destV6 = UInt128.random(in: 0...UInt128.max)
                let destV6Prefix = UInt.random(in: 0...128)
                let destV6String = "\(destV6.ipv6)/\(destV6Prefix)"
                let destV6cidr = Cidr(cidr: destV6String)!  //TODO get rid of !
                destString = " \(destV6cidr) "
                
                // deliberately using ipv4 protocol list for asa ipv6 pending better information
                ipProtocol = RandomAcl.protocols.randomElement()!  // rewriting
            }
        case .nxos,.arista:
            var sourceIp = UInt.random(in: 0...UInt(UInt32.max))
            let sourcePrefix = Ipv4Prefix.allCases.randomElement()!
            let sourceRemainder = sourceIp % sourcePrefix.dontCareHosts
            sourceIp = sourceIp - sourceRemainder
            
            var destIp = UInt.random(in: 0...UInt(UInt32.max))
            let destPrefix = Ipv4Prefix.allCases.randomElement()!
            let destRemainder = destIp % destPrefix.dontCareHosts
            destIp = destIp - destRemainder
            
            sourceString = "\(sourceIp.ipv4)/\(sourcePrefix.rawValue) "
            destString = " \(destIp.ipv4)/\(destPrefix.rawValue) "

        case .iosv6,.nxosv6,.iosxrv6,.aristav6:
            let sourceV6 = UInt128.random(in: 0...UInt128.max)
            let sourceV6Prefix = UInt.random(in: 0...128)
            let sourceV6String = "\(sourceV6.ipv6)/\(sourceV6Prefix)"
            let sourceV6cidr = Cidr(cidr: sourceV6String)!  //TODO get rid of !
            sourceString = "\(sourceV6cidr) "
            
            let destV6 = UInt128.random(in: 0...UInt128.max)
            let destV6Prefix = UInt.random(in: 0...128)
            let destV6String = "\(destV6.ipv6)/\(destV6Prefix)"
            let destV6cidr = Cidr(cidr: destV6String)!  //TODO get rid of !
            destString = " \(destV6cidr) "
        }
        let aclAction: AclAction = [.permit,.deny].randomElement()!
        
        let port1 = UInt.random(in: 0...UInt.MAXPORT)
        let port2 = UInt.random(in: 0...UInt.MAXPORT)
        let port3 = UInt.random(in: 0...UInt.MAXPORT)
        let port4 = UInt.random(in: 0...UInt.MAXPORT)
        let sourceLowPort, sourceHighPort, destLowPort, destHighPort: UInt
        if port1 < port2 {
            sourceLowPort = port1
            sourceHighPort = port2
        } else {
            sourceLowPort = port2
            sourceHighPort = port1
        }
        if port3 < port4 {
            destLowPort = port3
            destHighPort = port4
        } else {
            destLowPort = port4
            destHighPort = port3
        }
        let sourcePortOperator = PortOperator.allCases.randomElement()!
        let destPortOperator = PortOperator.allCases.randomElement()!
                
        var outputString = ""
        if deviceType == .asa {
            outputString.append("access-list 101 extended ")
        }
        if deviceType == .iosxr || deviceType == .iosxrv6 {
            let sequenceString = String(format: "%4d ", self.sequence)
            outputString.append(sequenceString)
        }
        outputString.append("\(aclAction) \(ipProtocol) ")
        switch deviceType {
        case .ios, .iosxr:
            outputString.append(sourceString)
        case .asa:
            outputString.append(sourceString)
        case .nxos,.arista:
            outputString.append(sourceString)
        case .nxosv6,.aristav6:
            outputString.append(sourceString)
        case .iosxrv6:
            outputString.append(sourceString)
        case .iosv6:
            outputString.append(sourceString)
        }
        switch ipProtocol {
        case "tcp","udp","6","17":
            switch sourcePortOperator {
            case .eq,.gt,.lt:
                outputString.append("\(sourcePortOperator) \(sourceLowPort)")
            case .ne:
                outputString.append("neq \(sourceLowPort)")
            case .range:
                outputString.append("\(sourcePortOperator) \(sourceLowPort) \(sourceHighPort)")
                //            case .nothing:
                //                sourcePortString = ""
            }
        default:
            break
        }//switch ipProtocol for source ports
        //outputString.append(" \(self.destIp.ipv4)")
        switch deviceType {
        case .ios, .iosxr:
            outputString.append(destString)
        case .asa:
            outputString.append(destString)
        case .nxos,.arista:
            outputString.append(destString)
        case .iosv6,.nxosv6,.iosxrv6,.aristav6:
            outputString.append(destString)
            
        }
        switch ipProtocol {
        case "tcp","udp","6","17":
            switch destPortOperator {
            case .eq,.gt,.lt:
                outputString.append("\(destPortOperator) \(destLowPort)")
            case .ne:
                outputString.append("neq \(destLowPort)")
            case .range:
                outputString.append("\(destPortOperator) \(destLowPort) \(destHighPort)")
                //            case .nothing:
                //                destPortString = ""
            }
        default:
            break
        }// switch ipProtocol for dest ports
        switch ipProtocol {
        case "tcp","6":
            if Bool.random() && deviceType != .asa {
                outputString.append(" established")
            } else {
                break
            }
        default:
            break
        }
        if Bool.random() {
            outputString.append( " log")
        }
        outputString.append("\n")
        self.myDescription = outputString
    }
    
    var description: String {
        return myDescription
    }
    
    static func operation() -> String {
        //let valid = Bool.random()
        let portOperator = PortOperator.allCases.randomElement()!
        var portOperatorString: String = ""
        let port1 = UInt.random(in: 0...UInt.MAXPORT)
        let port2 = UInt.random(in: 0...UInt.MAXPORT)
        switch portOperator {
        case .eq:
            portOperatorString = "\(portOperator) \(port1)"
        case .gt:
            portOperatorString = "\(portOperator) \(port1)"
        case .lt:
            portOperatorString = "\(portOperator) \(port1)"
        case .ne:
            portOperatorString = "\(portOperator) \(port1)"
        case .range:
            if port1 <= port2 {
                portOperatorString = "\(portOperator) \(port1) \(port2)"
            } else {
                portOperatorString = "\(portOperator) \(port2) \(port1)"
            }
        }//switch portOperator
        return portOperatorString
    }
}

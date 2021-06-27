//
//  AclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/8/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

enum AsaToken: Equatable {
    case unsupported(String)
    case accessList
    case extended
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case any4
    case any6
    case host
    case objectGroup
    case portOperator(PortOperator)
    case comment
    case log
    case fourOctet(UInt128)
    case number(UInt)
    case addressV6(UInt128)
    case cidrV6(IpRange)
    case name(String)
    
    init?(string: String) {
        switch string {
        case "line":
        //case "nexthop","vrf","fragments","authen","destopts","dscp","precedence":
            self = .unsupported(string)
        case "access-list":
            self = .accessList
        case "extended":
            self = .extended
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        case "object","object-group":
            self = .objectGroup
        case "deny":
            self = .action(.deny)
        case "log", "log-input":
            self = .log
        case "any":
            self = .any
        case "any4":
            self = .any4
        case "any6":
            self = .any6
        case "host":
            self = .host
        case "eq","gt","lt","ne","neq","ra","range":
            if let portOperator = PortOperator(string) {
                self = .portOperator(portOperator)
            } else {
                return nil
            }
        case "ahp","eigrp","esp","gre","icmp","igmp","igrp","ip","ipv4","ipinip","nos","ospf","pcp","pim","sctp","tcp","udp":
            if let ipProtocol = string.ipProtocol(deviceType: .asa) {
                self = .ipProtocol(ipProtocol)
            } else {
                debugPrint("Error decoding asaIpProtocol from \(string) DEVELOPER MUST FIX")
                return nil
            }
            
        default:
            if let number = UInt(string) {
                self = .number(number)
            } else if let ipv4Address = string.ipv4address {
                self = .fourOctet(ipv4Address)
            } else if let ipRangeV6 = IpRange(cidr: string) {
                // CIDR for IPv4 not allowed for ASA
                if ipRangeV6.ipVersion == .IPv4 {
                    return nil
                }
                self = .cidrV6(ipRangeV6)
            } else if let ipv6Address = IPv6Address(string) {
                self = .addressV6(ipv6Address.uint128)
            } else if string.first == "!" || string.first == "#" || string.first == ";" || string.first == ":" {
                self = .comment
            } else  {
                self = .name(string)
            }
        }
    }
}

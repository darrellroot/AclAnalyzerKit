//
//  AristaAclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 10/19/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum AristaAclToken: Equatable {
    case unsupported(String)
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    case portOperator(PortOperator)
    case comment
    case log
    case established
    case fourOctet(UInt128)
    case cidr(IpRange)
    case number(UInt)
    case name(String)
    
    init?(string: String) {
        switch string {
        case "dscp","fragments","tracked","hop-limit","ttl","ack","fin","psh","rst","syn","urg","dvmrp","host-query","host-report","trace":
            self = .unsupported(string)
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        case "deny":
            self = .action(.deny)
        case "log":
            self = .log
        case "ahp","icmp","igmp","ip","ospf","pim","tcp","udp","vrrp":
            if let ipProtocol = string.ipProtocol(deviceType: .arista) {
                self = .ipProtocol(ipProtocol)
            } else {
                return nil
            }
        case "any":
            self = .any
        case "host":
            self = .host
        case "eq","gt","lt","neq","range":
            if let portOperator = PortOperator(string) {
                self = .portOperator(portOperator)
            } else {
                return nil
            }
        case "established","est":
            self = .established
        default:
            if let number = UInt(string) {
                self = .number(number)
            } else if let ipRange = IpRange(cidr: string) {
                self = .cidr(ipRange)
            } else if let ipv4Address = string.ipv4address {
                self = .fourOctet(ipv4Address)
            } else if string.first == "!" || string.first == "#" || string.first == ";" || string.first == ":" {
                self = .comment
            } else  {
                self = .name(string)
            }
        }
    }
}

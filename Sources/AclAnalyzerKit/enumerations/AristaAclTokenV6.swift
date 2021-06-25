//
//  AristaAclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 10/22/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum AristaAclTokenV6: Equatable {
    case unsupported(String)
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    case portOperator(PortOperator)
    case comment
    case log
    case established
    case addressV6(UInt128)
    case cidrV6(IpRange)
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
        case "icmpv6","ipv6","ospf","tcp","udp":
            if let ipProtocol = string.ipProtocol(deviceType: .aristav6, delegate: nil, delegateWindow: nil) {
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
                self = .cidrV6(ipRange)
            } else if let ipv6Address = string.ipv6address {
                self = .addressV6(ipv6Address)
            } else if string.first == "!" || string.first == "#" || string.first == ";" || string.first == ":" {
                self = .comment
            } else  {
                self = .name(string)
            }
        }
    }
}

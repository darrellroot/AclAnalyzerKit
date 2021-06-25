//
//  NxAclTokenV6.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 8/31/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

enum NxAclTokenV6: Equatable {
    case unsupported(String)
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    case addrgroup
    case portgroup
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
        case "dscp","flow-label","fragments","time-range","packet-length","ack","fin","psh","rst","syn","urg":
            self = .unsupported(string)
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        case "addrgroup":
            self = .addrgroup
        case "portgroup":
            self = .portgroup
        case "deny":
            self = .action(.deny)
        case "log":
            self = .log
        case "ahp","esp","icmp","ipv6","pcp","sctp","tcp","udp":
            if let ipProtocol = string.ipProtocol(deviceType: .nxosv6, delegate: nil, delegateWindow: nil) {
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
            } else if let ipRangeV6 = IpRange(cidr: string) {
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

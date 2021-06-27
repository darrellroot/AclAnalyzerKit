//
//  AclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/8/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

enum IosTokenV6: Equatable {
    case unsupported(String)
    //case accessList
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    //case objectGroup
    case portOperator(PortOperator)
    case comment
    case log
    case sequence
    case established
    case addressV6(UInt128)
    case cidrV6(IpRange)
    case number(UInt)
    case name(String)
    
    init?(string: String) {
        switch string {
        case "precedence","dscp","tos","time-range","fragments","timeout","reflect","option","match-any","match-all":
            self = .unsupported(string)
        //case "access-list":
        //    self = .accessList
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        //case "object-group":
            //self = .objectGroup
        case "deny":
            self = .action(.deny)
        case "log", "log-input":
            self = .log
        case "any":
            self = .any
        case "sequence":
            self = .sequence
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
        case "ahp","esp","hbh","icmp","ipv6","pcp","sctp","tcp","udp":
            //"ahp","eigrp","esp","gre","icmp","igmp","igrp","ipv6","ipinip","nos","ospf","pcp","pim","tcp","udp":
            if let ipProtocol = string.ipProtocol(deviceType: .iosv6) {
                self = .ipProtocol(ipProtocol)
            } else {
                return nil
            }
            
        default:
            //let splitString = string.split(separator: "/")
            if let number = UInt(string) {
                self = .number(number)
            } else if let ipv6Address = IPv6Address(string) {
                self = .addressV6(ipv6Address.uint128)
            } else if let ipRangeV6 = IpRange(cidr: string) {
                self = .cidrV6(ipRangeV6)
            } else if string.first == "!" || string.first == "#" || string.first == ";" || string.first == ":" {
                self = .comment
            } else  {
                self = .name(string)
            }
        }
    }
}

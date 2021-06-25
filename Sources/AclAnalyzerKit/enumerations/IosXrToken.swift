//
//  AclToken.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/8/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum IosXrToken: Equatable {
    case unsupported(String)
    case action(AclAction)
    case ipProtocol(UInt)
    case any
    case host
    case netgroup
    case counter
    case portgroup
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
        case "nexthop","vrf","fragments","authen","destopts","dscp","precedence":
            self = .unsupported(string)
        case "remark":
            self = .comment
        case "permit":
            self = .action(.permit)
        case "deny":
            self = .action(.deny)
        case "log", "log-input":
            self = .log
        case "counter":
            self = .counter
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
        case "net-group":
            self = .netgroup
        case "port-group":
            self = .portgroup
        case "ahp","eigrp","esp","gre","icmp","igmp","igrp","ip","ipv4","ipinip","nos","ospf","pcp","pim","tcp","udp":
            if let ipProtocol = string.ipProtocol(deviceType: .iosxr, delegate: nil, delegateWindow: nil) {
                self = .ipProtocol(ipProtocol)
            } else {
                return nil
            }
            
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

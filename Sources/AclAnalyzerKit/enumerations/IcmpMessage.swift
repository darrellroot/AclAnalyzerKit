//
//  IcmpMessage.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/16/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct IcmpMessage {
    let type: UInt
    var code: UInt? = nil
    
    init?(type: UInt, code: UInt? = nil) {
        guard type < 256 else {
            return nil
        }
        if let code = code {
            guard code < 256 else {
                return nil
            }
        }
        self.type = type
        self.code = code
    }
    init?(deviceType: DeviceType, message: String) {
        switch deviceType {
        case .arista,.aristav6:
            switch message {
            case "administratively-prohibited":
                self.type = 3
                self.code = 13
            case "alternate-address":
                self.type = 6
            case "conversion-error":
                self.type = 31
            case "dod-host-prohibited":
                self.type = 3
                self.code = 10
            case "dod-net-prohibited":
                self.type = 3
                self.code = 9
            case "echo":
                self.type = 8
            case "echo-reply":
                self.type = 0
            case "general-parameter-problem":
                self.type = 12
                self.code = 0
            case "host-isolated":
                self.type = 3
                self.code = 8
            case "host-precedence-unreachable":
                self.type = 3
                self.code = 14
            case "host-redirect":
                self.type = 5
                self.code = 1
            case "host-tos-redirect":
                self.type = 5
                self.code = 3
            case "host-tos-unreachable":
                self.type = 3
                self.code = 12
            case "host-unknown":
                self.type = 3
                self.code = 7
            case "host-unreachable":
                self.type = 3
                self.code = 1
            case "information-reply":
                self.type = 16
            case "information-request":
                self.type = 15
            case "mask-reply":
                self.type = 18
            case "mask-request":
                self.type = 17
            case "mobile-host-redirect":
                self.type = 32
            case "net-redirect":
                self.type = 5
                self.code = 0
            case "net-tos-redirect":
                self.type = 5
                self.code = 2
            case "net-tos-unreachable":
                self.type = 3
                self.code = 11
            case "net-unreachable":
                self.type = 3
                self.code = 0
            case "network-unknown":
                self.type = 3
                self.code = 6
            case "no-room-for-option":
                self.type = 12
                self.code = 2
            case "option-missing":
                self.type = 12
                self.code = 1
            case "packet-too-big":
                self.type = 3
                self.code = 4
            case "parameter-problem":
                self.type = 12
            case "port-unreachable":
                self.type = 3
                self.code = 3
            case "precedence-unreachable":
                self.type = 3
                self.code = 15
            case "protocol-unreachable":
                self.type = 3
                self.code = 2
            case "reassembly-timeout":
                self.type = 11
                self.code = 1
            case "redirect":
                self.type = 5
            case "router-advertisement":
                self.type = 9
            case "router-solicitation":
                self.type = 10
            case "source-quench":
                self.type = 4
            case "source-route-failed":
                self.type = 3
                self.code = 5
            case "time-exceeded":
                self.type = 11
            case "timestamp-reply":
                self.type = 14
            case "timestamp-request":
                self.type = 13
            case "traceroute":
                self.type = 30
            case "ttl-exceeded":
                self.type = 11
                self.code = 0
            case "unreachable":
                self.type = 3
            default:
                return nil

            }
        case .asa:
            switch message {
            case "echo-reply":
                self.type = 0
            case "unreachable":
                self.type = 3
            case "source-quench":
                self.type = 4
            case "redirect":
                self.type = 5
            case "alternate-address":
                self.type = 6
            case "echo":
                self.type = 8
            case "router-advertisement":
                self.type = 9
            case "router-solicitation":
                self.type = 10
            case "time-exceeded":
                self.type = 11
            case "parameter-problem":
                self.type = 12
            case "timestamp-request":
                self.type = 13
            case "timestamp-reply":
                self.type = 14
            case "information-request":
                self.type = 15
            case "information-reply":
                self.type = 16
            case "address-mask-request","mask-request":
                self.type = 17
            case "address-mask-reply","mask-reply":
                self.type = 18
            case "traceroute":
                self.type = 30
            case "conversion-error":
                self.type = 31
            case "mobile-redirect":
                self.type = 32
            default:
                return nil
            }
        case .ios, .nxos, .iosxr,.iosv6,.nxosv6,.iosxrv6:
            switch message {
            case "administratively-prohibited":
                self.type = 3
                self.code = 13
            case "alternate-address":
                self.type = 6
            case "conversion-error":
                self.type = 31
            case "dod-host-prohibited":
                self.type = 3
                self.code = 10
            case "dod-net-prohibited":
                self.type = 3
                self.code = 9
            case "echo":
                self.type = 8
            case "echo-reply":
                self.type = 0
            case "general-parameter-problem":
                self.type = 12
            case "host-isolated":
                self.type = 3
                self.code = 8
            case "host-precedence-unreachable":
                self.type = 3
                self.code = 14
            case "host-redirect":
                self.type = 5
                self.code = 1
            case "host-tos-redirect":
                self.type = 5
                self.code = 3
            case "host-tos-unreachable":
                self.type = 3
                self.code = 12
            case "host-unknown":
                self.type = 3
                self.code = 7
            case "host-unreachable":
                self.type = 3
                self.code = 1
            case "information-reply":
                self.type = 16
            case "information-request":
                self.type = 15
            case "mask-reply":
                self.type = 18
            case "mask-request":
                self.type = 17
            case "mobile-redirect":
                self.type = 32
            case "net-redirect":
                self.type = 5
                self.code = 0
            case "net-tos-redirect":
                self.type = 5
                self.code = 2
            case "net-tos-unreachable":
                self.type = 3
                self.code = 11
            case "net-unreachable":
                self.type = 3
                self.code = 0
            case "network-unknown":
                self.type = 3
                self.code = 6
            case "no-room-for-option":
                //TODO FIX THIS
                return nil
            case "option-missing":
                self.type = 12
                self.code = 1
            case "packet-too-big":
                self.type = 3
                self.code = 4
            case "parameter-problem":
                self.type = 12
            case "port-unreachable":
                self.type = 3
                self.code = 3
            case "precedence-unreachable":
                self.type = 3
                self.code = 14
            case "protocol-unreachable":
                self.type = 3
                self.code = 2
            case "reassembly-timeout":
                self.type = 11
                self.code = 1
            case "redirect":
                self.type = 5
            case "router-advertisement":
                self.type = 9
            case "router-solicitation":
                self.type = 10
            case "source-quench":
                self.type = 4
            case "source-route-failed":
                self.type = 3
                self.code = 5
            case "time-exceeded":
                self.type = 11
            case "timestamp-reply":
                self.type = 14
            case "timestamp-request":
                self.type = 13
            case "traceroute":
                self.type = 30
            case "ttl-exceeded":
                self.type = 11
            case "unreachable":
                self.type = 3
            default:
                return nil
            }
        }
    }
}

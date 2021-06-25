//
//  Cidr.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation
import Network

struct Cidr: CustomStringConvertible, Equatable {
        
    let minIp: UInt128
    let maxIp: UInt128
    var bitAligned: Bool = true // set to false if initialized with non perfectly aligned ip
    let ipVersion: IpVersion
    let prefix: UInt128
    
    var description: String {
        switch self.ipVersion {
        case .IPv4:
            return "\(self.minIp.ipv4)/\(self.prefix)"
        case .IPv6:
            return "\(self.minIp.ipv6)/\(self.prefix)"
        }
    }
    
    init?(cidr: String) {
        
        func power(_ x: UInt128, _ y: UInt128) -> UInt128 {
            var result: UInt128 = 1
            for _ in 0..<y {
                result = x * result
            }
            return result
        }

        let portions = cidr.split(separator: "/")
        guard portions.count == 2 else { return nil }
        guard let ipSubstring = portions.first else { return nil }
        guard let lengthString = portions.last else { return nil }
        let octets = ipSubstring.split(separator: ".")
        let ipv6 = IPv6Address(String(ipSubstring))
        if ipv6 == nil && octets.count != 4 { return nil }
        if let ipv6 = ipv6 {  //IPv6 case
            self.ipVersion = .IPv6
            guard let length = UInt128(lengthString) else { return nil }
            guard length >= 0 && length <= 128 else { return nil }
            self.prefix = length
            let ip = UInt128(ipv6: ipv6)
            if length == 0 {
                self.minIp = 0
                self.maxIp = UInt128.max
                if ip != 0 {
                    self.bitAligned = false
                }
                return
            } else {
                let numHosts: UInt128 = 1 << (128 - length)
                let minIp = (ip >> (128 - length)) << (128 - length)
                let remainder = ip - minIp
                //let numHosts = power(2, 128 - length)
                //let remainder = ip % numHosts
                if remainder > 0 {
                    self.bitAligned = false
                }
                self.minIp = ip - remainder
                if self.minIp > 0 {
                    self.maxIp = self.minIp - 1 + numHosts
                } else {
                    self.maxIp = numHosts - 1
                }
                return
            }
        } else {  // IPv4 case
            self.ipVersion = .IPv4
            guard let octet1 = UInt8(octets[0]) else { return nil }
            guard let octet2 = UInt8(octets[1]) else { return nil }
            guard let octet3 = UInt8(octets[2]) else { return nil }
            guard let octet4 = UInt8(octets[3]) else { return nil }
            let passedInAddress: UInt128 = UInt128(octet1) * 256 * 256 * 256 + UInt128(octet2) * 256 * 256 + UInt128(octet3) * 256 + UInt128(octet4)
            guard let length = UInt128(lengthString) else { return nil }
            guard length >= 0 && length <= 32 else { return nil }
            self.prefix = length
            let numHosts = power(UInt128(2),(32 - length))
            let remainder = passedInAddress % numHosts
            let baseAddress: UInt128
            if remainder > 0 {
                bitAligned = false
                baseAddress = passedInAddress - remainder
            } else {
                baseAddress = passedInAddress
            }
            self.minIp = baseAddress
            self.maxIp = baseAddress + numHosts - 1
            return
        }
        
    }
}

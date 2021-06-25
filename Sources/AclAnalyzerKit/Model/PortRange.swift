//
//  IpRange.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/28/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

struct PortRange: CustomStringConvertible {
    
    static let ANYPORTRANGE = PortRange(minPort: 0, maxPort: UInt(UInt16.max))!

    let minPort: UInt
    let maxPort: UInt
    var serviceType: ServiceType?  // only non-nil for service object groups
    
    var description: String {
        if minPort == maxPort {
            return "\(self.minPort)"
        } else {
            return "\(self.minPort)-\(self.maxPort)"
        }
    }
    
    init?(minPort: UInt, maxPort: UInt) {  // requires valid minSourceIp and maxSourceIp
        guard minPort >= 0 && maxPort >= 0 && minPort <= 65535 && maxPort <= 65535 && minPort <= maxPort else {
            return nil
        }
        self.minPort = minPort
        self.maxPort = maxPort
    }
    
    public func contains(ipProtocol: UInt, port: UInt) -> Bool {
        if self.serviceType == .tcp && ipProtocol != 6 {
            return false
        }
        if self.serviceType == .udp && ipProtocol != 17 {
            return false
        }
        if port >= minPort && port <= maxPort {
            return true
        } else {
            return false
        }
    }
}

//
//  ObjectGroup.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/29/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

class ObjectGroupService {
    let type: ServiceType
    var portRanges: [PortRange] = []
    
    init(type: ServiceType) {
        self.type = type
    }
    func append(portRange: PortRange) {
        var portRange = portRange
        portRange.serviceType = self.type
        self.portRanges.append(portRange)
    }
    var count: Int {
        return portRanges.count
    }
    func contains(ipProtocol: UInt, port: UInt) -> Bool {
        switch ipProtocol {
        case 6: //tcp
            if type == .udp {
                return false
            }
        case 17: //udp
            if type == .tcp {
                return false
            }
        default: // any other protocol does not have ports
            return false
        }
        // ok, protocol matches service type.  lets see if port matches
        for range in portRanges {
            if port >= range.minPort && port <= range.maxPort {
                return true
            }
        }
        return false
    }
}

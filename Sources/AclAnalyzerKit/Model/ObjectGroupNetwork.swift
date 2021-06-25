//
//  ObjectGroup.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/29/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

class ObjectGroupNetwork {
    var ipRanges: [IpRange] = []
    
    init() {
    }
    func append(ipRange: IpRange) {
        self.ipRanges.append(ipRange)
    }
    var count: Int {
        return ipRanges.count
    }
}

//
//  ObjectGroup.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/29/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

class ObjectGroupProtocol {
    var ipProtocols: [UInt] = []
    
    init() {
        //no need to do anything, name is in the parent data structure
    }
    func append(ipProtocol: UInt) {
        if ipProtocol < 0 || ipProtocol > 255 {
            debugPrint("Error invalid ip protocol \(ipProtocol)")
        }
        self.ipProtocols.append(ipProtocol)
    }
    var count: Int {
        return ipProtocols.count
    }
}

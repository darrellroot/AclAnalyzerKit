//
//  PortOperator.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/7/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum PortOperator: String, CaseIterable {
    case eq
    case gt
    case lt
    case ne
    case range
    
    init?(_ string: String) {
        switch string {
        case "eq":
            self = .eq
        case "gt":
            self = .gt
        case "lt":
            self = .lt
        case "ne","neq":
            self = .ne
        case "range":
            self = .range
        default:
            return nil
        }
    }
}

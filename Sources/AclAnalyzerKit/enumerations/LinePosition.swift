//
//  LinePosition.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/17/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum LinePosition: String {
    case beginning
    case accessList
    case listName
    case action
    case ipProtocol
    case protocolObjectGroup
    case sourceIp
    case sourceObjectGroup
    case sourceIpHost
    case sourceMask
    case sourcePortOperator
    case firstSourcePort
    case lastSourcePort
    case destIp
    case destIpHost
    case destObjectGroup
    case destMask
    case destPortOperator
    case firstDestPort
    case lastDestPort
    case destObjectService
    case comment
    case remark
    case log
    case logInterval
    case end
}

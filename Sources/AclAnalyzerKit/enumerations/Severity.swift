//
//  Severity.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum Severity: String, CustomStringConvertible {
    case error
    case warning
    case notification
    //case linetext
    case result
    case blank
    
    var description: String {
        switch self {
        
        case .error:
            return "ERROR"
        case .warning:
            return "WARNING"
        case .notification:
            return "NOTIFICATION"
        //case .linetext:
        //    return "LINETEXT"
        case .result:
            return "RESULT"
        case .blank:
            return ""
        }
    }
}

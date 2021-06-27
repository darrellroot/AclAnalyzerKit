//
//  File.swift
//  
//
//  Created by Darrell Root on 6/25/21.
//

import Foundation

struct AclError: Error,CustomStringConvertible {
    
    let linenum: Int
    let line: String
    let severity: Severity
    let message: String
    
    var description: String {  // returns two lines
        return "LINE \(linenum) \(line)\n\(severity) \(message)\n"
    }

}

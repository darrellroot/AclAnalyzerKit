//
//  AclErrorReporting.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/13/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

protocol ErrorDelegate {
    func report(severity: Severity, message: String, line: Int, delegateWindow: DelegateWindow?)
    func report(severity: Severity, message: String, delegateWindow: DelegateWindow?)
}

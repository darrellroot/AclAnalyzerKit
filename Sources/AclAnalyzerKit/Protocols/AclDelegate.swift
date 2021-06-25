//
//  AclDelegate.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/30/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

protocol AclDelegate {
    func getObjectGroupNetwork(_ group: String) -> ObjectGroupNetwork?
    func getObjectGroupService(_ group: String) -> ObjectGroupService?
    func getObjectGroupProtocol(_ group: String) -> ObjectGroupProtocol?
    func getHostname(_ hostname: String) -> UInt128?   // must be < UInt32.max
    func foundName(_ name: String, delegateWindow: DelegateWindow?)
}

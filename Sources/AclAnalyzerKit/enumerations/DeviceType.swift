//
//  AceType.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/18/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum DeviceType: String, CaseIterable, Hashable {
    case ios
    case iosv6
    case asa
    case nxos
    case nxosv6
    case iosxr
    case iosxrv6
    case arista
    case aristav6
}

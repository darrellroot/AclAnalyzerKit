//
//  ServiceType.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/4/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum ServiceType {
    case tcp
    case udp
    case tcpAndUdp
    case none      //means service type not specified on asa
}

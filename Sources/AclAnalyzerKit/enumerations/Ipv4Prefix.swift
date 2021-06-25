//
//  Ipv4Prefix.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 7/24/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

enum Ipv4Prefix: UInt, CaseIterable {
    case slash0
    case slash1
    case slash2
    case slash3
    case slash4
    case slash5
    case slash6
    case slash7
    case slash8
    case slash9
    case slash10
    case slash11
    case slash12
    case slash13
    case slash14
    case slash15
    case slash16
    case slash17
    case slash18
    case slash19
    case slash20
    case slash21
    case slash22
    case slash23
    case slash24
    case slash25
    case slash26
    case slash27
    case slash28
    case slash29
    case slash30
    case slash31
    case slash32
    
    var dontCareBits: String {
        return (self.dontCareHosts - 1).ipv4
    }
    var dontCareHosts: UInt {
        let dontCareArray: [UInt] = [0,1,3,7,15,31,63,127,255,511,1023,2047,4095,8191,16383,32767,65535,131071,262143,524287,1048575,2097151,4194303,8388607,16777215,33554431,67108863,134217727,268435455,536870911,1073741823,2147483647,4294967295].reversed()
        return dontCareArray[Int(self.rawValue)] + 1
    }
    var netmask: String {
        return (UInt.MAXIPV4 + 1 - self.dontCareHosts).ipv4
    }
}

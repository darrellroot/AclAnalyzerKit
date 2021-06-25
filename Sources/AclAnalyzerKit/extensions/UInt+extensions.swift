//
//  UInt+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 5/17/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

extension UInt {
    static var MAXIPV4: UInt {
        return UInt(UInt32.max)
    }
    static var MAXPORT: UInt {
        return UInt(UInt16.max)
    }
    var dontCareHosts: UInt? {
        // returns number of hosts in a dont care bit range
        switch self {
        case 1,3,7,15,31,63,127,255,511,1023,2047,4095,8191,16383,32767,65535,131071,262143,524287,1048575,2097151,4194303,8388607,16777215,33554431,67108863,134217727,268435455,536870911,1073741823,2147483647:
            return self + 1
        case
        0,4294967295:
            return self + 1
        default:
            return nil
        }
    }
    var netmaskHosts: UInt? {
        // returns number of hosts in a netmask range
        switch self {
        case
        2147483648,     /*128.0.0.0*/
        3221225472,     /*192.0.0.0*/
        3758096384,     /*224.0.0.0*/
        4026531840,     /*240.0.0.0*/
        4160749568,     /*248.0.0.0*/
        4227858432,     /*252.0.0.0*/
        4261412864,     /*254.0.0.0*/
        4278190080,     /*255.0.0.0*/
        4286578688,     /*255.128.0.0*/
        4290772992,     /*255.192.0.0*/
        4292870144,     /*255.224.0.0*/
        4293918720,     /*255.240.0.0*/
        4294443008,     /*255.248.0.0*/
        4294705152,     /*255.252.0.0*/
        4294836224,     /*255.254.0.0*/
        4294901760,     /*255.255.0.0*/
        4294934528,     /*255.255.128.0*/
        4294950912,     /*255.255.192.0*/
        4294959104,     /*255.255.224.0*/
        4294963200,     /*255.255.240.0*/
        4294965248,     /*255.255.248.0*/
        4294966272,     /*255.255.252.0*/
        4294966784,     /*255.255.254.0*/
        4294967040,     /*255.255.255.0*/
        4294967168,     /*255.255.255.128*/
        4294967232,     /*255.255.255.192*/
        4294967264,     /*255.255.255.224*/
        4294967280,     /*255.255.255.240*/
        4294967288,     /*255.255.255.248*/
        4294967292,     /*255.255.255.252*/
        4294967294:     /*255.255.255.254*/
            return 4294967296 - self
        case 4294967295:
            return 1
        case 0:
            return 4294967296
        default:
            return nil
        }
    }
    var maskType: MaskType? {
        switch self {
        case 1,3,7,15,31,63,127,255,511,1023,2047,4095,8191,16383,32767,65535,131071,262143,524287,1048675,2097151,4194303,8388607,16777215,33554431,67108863,134217727,268435455,536870911,1073741823,2147483647:
            return .dontCareBit
        case 0,4294967295:
            // could be either netmask /0 or dont care bit 255.255.255.255
            return .either
        case
        2147483648,     /*128.0.0.0*/
        3221225472,     /*192.0.0.0*/
        3758096384,     /*224.0.0.0*/
        4026531840,     /*240.0.0.0*/
        4160749568,     /*248.0.0.0*/
        4227858432,     /*252.0.0.0*/
        4261412864,     /*254.0.0.0*/
        4278190080,     /*255.0.0.0*/
        4286578688,     /*255.128.0.0*/
        4290772992,     /*255.192.0.0*/
        4292870144,     /*255.224.0.0*/
        4293918720,     /*255.240.0.0*/
        4294443008,     /*255.248.0.0*/
        4294705152,     /*255.252.0.0*/
        4294836224,     /*255.254.0.0*/
        4294901760,     /*255.255.0.0*/
        4294934528,     /*255.255.128.0*/
        4294950912,     /*255.255.192.0*/
        4294959104,     /*255.255.224.0*/
        4294963200,     /*255.255.240.0*/
        4294965248,     /*255.255.248.0*/
        4294966272,     /*255.255.252.0*/
        4294966784,     /*255.255.254.0*/
        4294967040,     /*255.255.255.0*/
        4294967168,     /*255.255.255.128*/
        4294967232,     /*255.255.255.192*/
        4294967264,     /*255.255.255.224*/
        4294967280,     /*255.255.255.240*/
        4294967288,     /*255.255.255.248*/
        4294967292,     /*255.255.255.252*/
        4294967294:     /*255.255.255.254*/
            return .netmask
        default:
            return nil
        }
    }
    var ipv4: String {
        let octet1 = self / (256 * 256 * 256)
        let octet2 = (self / (256 * 256)) % 256
        let octet3 = (self / 256) % 256
        let octet4 = self % 256
        return "\(octet1).\(octet2).\(octet3).\(octet4)"
    }
    var ipProto: String {
        switch self {
        case 0:
            return "ip"
        case 6:
            return "tcp"
        case 17:
            return "udp"
        default:
            return "\(self)"
        }
    }

}


/* Playground for netmask math
 
 import Cocoa
 
 func pow(_ x: Int, _ y: Int) -> Int {
 var result = 1
 for i in 0..<y {
 result *= x
 }
 return result
 }
 let numbers = [128,192,224,240,248,252,254,255]
 
 var str = "Hello, playground"
 var octet1 = 0
 var octet2 = 0
 var octet3 = 0
 var octet4 = 0
 for loop in 0...7 {
 octet1 = numbers[loop]
 let total = octet1 * 256 * 256 * 256 + octet2 * 256 * 256 + octet3 * 256 + octet4
 print("\(total)     /*\(octet1).\(octet2).\(octet3).\(octet4)*/")
 }
 for loop in 0...7 {
 octet2 = numbers[loop]
 let total = octet1 * 256 * 256 * 256 + octet2 * 256 * 256 + octet3 * 256 + octet4
 print("\(total)     /*\(octet1).\(octet2).\(octet3).\(octet4)*/")
 }
 for loop in 0...7 {
 octet3 = numbers[loop]
 let total = octet1 * 256 * 256 * 256 + octet2 * 256 * 256 + octet3 * 256 + octet4
 print("\(total)     /*\(octet1).\(octet2).\(octet3).\(octet4)*/")
 }
 for loop in 0...7 {
 octet4 = numbers[loop]
 let total = octet1 * 256 * 256 * 256 + octet2 * 256 * 256 + octet3 * 256 + octet4
 print("\(total)     /*\(octet1).\(octet2).\(octet3).\(octet4)*/")
 }
 
 
 */

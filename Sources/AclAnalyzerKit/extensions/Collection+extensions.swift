//
//  Collection+extensions.swift
//  Network Mom ACL Analyzer
//
//  Created by Darrell Root on 6/18/19.
//  Copyright © 2019 Network Mom LLC. All rights reserved.
//

import Foundation

extension Collection {
    
    /// Returns the element at the specified index if it is within bounds, otherwise nil.
    subscript (safe index: Index) -> Element? {
        return indices.contains(index) ? self[index] : nil
    }
}

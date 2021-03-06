// This is only here because qpack is new and quinn no uses it yet.
// TODO remove allow dead code
#![allow(dead_code)]

use std::borrow::Cow;


/**
 * https://tools.ietf.org/html/rfc7541
 * 4.1.  Calculating Table Size
 */
pub const ESTIMATED_OVERHEAD_BYTES: usize = 32;


#[derive(Debug, PartialEq, Clone)]
pub struct HeaderField {
    pub name: Cow<'static, [u8]>,
    pub value: Cow<'static, [u8]>
}


impl HeaderField {
    pub fn new<T, S>(name: T, value: S) -> HeaderField
        where T: Into<Vec<u8>>,
              S: Into<Vec<u8>> {
        HeaderField {
            name: Cow::Owned(name.into()),
            value: Cow::Owned(value.into())
        }
    }
    
    pub fn mem_size(&self) -> usize {
        self.name.len() + self.value.len() + ESTIMATED_OVERHEAD_BYTES
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    /**
     * https://tools.ietf.org/html/rfc7541#section-4.1
     * "The size of an entry is the sum of its name's length in octets (as
     *  defined in Section 5.2), its value's length in octets, and 32."
     * "The size of an entry is calculated using the length of its name and
     *  value without any Huffman encoding applied."
     */
    #[test]
    fn test_field_size_is_offset_by_32() {
        let field = HeaderField { 
            name: Cow::Borrowed(b"Name"),
            value: Cow::Borrowed(b"Value")
        };
        assert_eq!(field.mem_size(), 4 + 5 + 32);
    }

}

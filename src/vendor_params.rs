//! Serde support for UniMRCP vendor specific parameters.

use crate::ffi;
use serde::{
    de::{DeserializeSeed, MapAccess, Visitor},
    Deserialize, Deserializer,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("serde: {0}")]
    Serde(String),
}

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(t: T) -> Self {
        Error::Serde(t.to_string())
    }
}

/// Deserialize a struct from an array of vendor specific parameters.
pub unsafe fn from_header_array<'a, T>(header: *mut ffi::apt_pair_arr_t) -> Result<T>
where
    T: Deserialize<'a>,
{
    let mut deserializer = HeaderDeserializer { header, index: 0 };
    let t = T::deserialize(&mut deserializer)?;
    Ok(t)
}

struct HeaderDeserializer {
    header: *mut ffi::apt_pair_arr_t,
    index: i32,
}

impl<'de, 'a> Deserializer<'de> for &'a mut HeaderDeserializer {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let pair = unsafe { ffi::apt_pair_array_get(self.header, self.index) };
        let s = unsafe { (*pair).value.as_str() };
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_map<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_map(KeyValueList::new(&mut self))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let pair = unsafe { ffi::apt_pair_array_get(self.header, self.index) };
        let s = unsafe { (*pair).value.as_str() };
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let pair = unsafe { ffi::apt_pair_array_get(self.header, self.index) };
        let s = unsafe { (*pair).value.as_str() };
        visitor.visit_string(s.to_string())
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let pair = unsafe { ffi::apt_pair_array_get(self.header, self.index) };
        let s = unsafe { (*pair).value.as_str() };
        let value = s.parse().map_err(serde::de::Error::custom)?;
        visitor.visit_bool(value)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let pair = unsafe { ffi::apt_pair_array_get(self.header, self.index) };
        match unsafe { (*pair).value }.length {
            0 => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let pair = unsafe { ffi::apt_pair_array_get(self.header, self.index) };
        let s = unsafe { (*pair).name.as_str() };
        visitor.visit_borrowed_str(s)
    }

    serde::forward_to_deserialize_any! {
            i8 i16 i32 i64 i128
            u8 u16 u32 u64 u128
            f32 f64
            char bytes byte_buf
            unit unit_struct newtype_struct seq tuple
            tuple_struct enum ignored_any
    }
}

struct KeyValueList<'a> {
    de: &'a mut HeaderDeserializer,
}

impl<'a> KeyValueList<'a> {
    fn new(de: &'a mut HeaderDeserializer) -> Self {
        KeyValueList { de }
    }
}

impl<'de, 'a> MapAccess<'de> for KeyValueList<'a> {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: DeserializeSeed<'de>,
    {
        let size = unsafe { ffi::apt_pair_array_size_get(self.de.header) };
        if self.de.index == size {
            Ok(None)
        } else {
            seed.deserialize(&mut *self.de).map(Some)
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: DeserializeSeed<'de>,
    {
        let result = seed.deserialize(&mut *self.de);
        self.de.index += 1;
        result
    }
}

#[derive(Default, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct VendorHeaders {
    #[serde(rename = "com.deepgram.model")]
    pub model: Option<String>,

    #[serde(rename = "com.deepgram.numerals")]
    pub numerals: Option<bool>,

    #[serde(rename = "com.deepgram.ner")]
    pub ner: Option<bool>,

    #[serde(rename = "com.deepgram.no_delay")]
    pub no_delay: Option<bool>,

    #[serde(rename = "com.deepgram.plugin")]
    pub plugin: Option<String>,

    #[serde(rename = "com.deepgram.keywords")]
    pub keywords: Option<String>,

    #[serde(rename = "com.deepgram.keyword_boost")]
    pub keyword_boost: Option<String>,

    #[serde(rename = "com.deepgram.vad_turnoff")]
    pub vad_turnoff: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi;
    use pretty_assertions::assert_eq;

    /// Wrapper for `apt_pair_arr_t`
    pub struct AptPairArray {
        allocator: *mut ffi::apr_allocator_t,
        pool: *mut ffi::apr_pool_t,
        array: *mut ffi::apt_pair_arr_t,
    }

    impl AptPairArray {
        /// Creates a new pair array
        pub fn new() -> Self {
            use std::mem::MaybeUninit;

            let mut tmp = AptPairArray {
                allocator: unsafe { MaybeUninit::uninit().assume_init() },
                pool: unsafe { MaybeUninit::uninit().assume_init() },
                array: unsafe { MaybeUninit::uninit().assume_init() },
            };

            unsafe {
                ffi::apr_initialize();
                ffi::apr_allocator_create(&mut tmp.allocator);
                ffi::apr_pool_create_unmanaged_ex(&mut tmp.pool, None, tmp.allocator);
                tmp.array = ffi::apt_pair_array_create(5, tmp.pool);
            };

            tmp
        }

        /// Add a new entry to the array pair
        pub fn add(&mut self, name: String, value: String) {
            use std::ffi::CString;
            let c_name = CString::new(name).expect("Name should not contain a \0 character");
            let c_value = CString::new(value).expect("Value should not contain a \0 character");

            let apt_name = &ffi::apt_str_t {
                length: c_name.as_bytes().len(),
                buf: c_name.into_raw(),
            };
            let apt_value = &ffi::apt_str_t {
                length: c_value.as_bytes().len(),
                buf: c_value.into_raw(),
            };

            unsafe {
                ffi::apt_pair_array_append(self.array, apt_name, apt_value, self.pool);
            }

            // Claim back, else a segmentation fault will be caused
            let _ = unsafe { CString::from_raw(apt_name.buf) };
            let _ = unsafe { CString::from_raw(apt_value.buf) };
        }
    }

    // Clean up C resources when done
    impl Drop for AptPairArray {
        fn drop(&mut self) {
            unsafe {
                ffi::apr_pool_destroy(self.pool);
                ffi::apr_allocator_destroy(self.allocator);
                ffi::apr_terminate();
            }
        }
    }

    #[test]
    fn parse_no_value() -> Result<()> {
        let arr = AptPairArray::new();
        let actual: VendorHeaders = unsafe { from_header_array(arr.array)? };
        let expected = VendorHeaders::default();

        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn parse_all_values() -> Result<()> {
        let mut arr = AptPairArray::new();
        arr.add("com.deepgram.model".to_string(), "basic".to_string());
        arr.add("com.deepgram.numerals".to_string(), "false".to_string());
        arr.add("com.deepgram.ner".to_string(), "true".to_string());
        arr.add("com.deepgram.no_delay".to_string(), "true".to_string());
        arr.add(
            "com.deepgram.plugin".to_string(),
            "noise,static".to_string(),
        );
        arr.add("com.deepgram.keywords".to_string(), "property".to_string());
        arr.add(
            "com.deepgram.keyword_boost".to_string(),
            "agent".to_string(),
        );
        arr.add("com.deepgram.vad_turnoff".to_string(), "500".to_string());

        let actual: VendorHeaders = unsafe { from_header_array(arr.array)? };
        let expected = VendorHeaders {
            model: Some("basic".to_string()),
            numerals: Some(false),
            ner: Some(true),
            no_delay: Some(true),
            plugin: Some("noise,static".to_string()),
            keywords: Some("property".to_string()),
            keyword_boost: Some("agent".to_string()),
            vad_turnoff: Some("500".to_string()),
        };

        assert_eq!(actual, expected);

        Ok(())
    }

    #[test]
    fn parse_extra_values_are_ignored() -> Result<()> {
        let mut arr = AptPairArray::new();
        arr.add("com.deepgram.unknown".to_string(), "true".to_string());
        arr.add("com.other.model".to_string(), "basic".to_string());

        let actual: VendorHeaders = unsafe { from_header_array(arr.array)? };
        let expected = VendorHeaders::default();

        assert_eq!(actual, expected);

        Ok(())
    }
}

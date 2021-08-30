//! Serde support for APR tables.

use crate::ffi;
use serde::{
    de::{DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{
    ffi::{CStr, CString},
    fmt,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("internal")]
    Internal,

    #[error("not supported")]
    NotSupported,

    #[error("not found")]
    NotFound,

    #[error("serde: {0}")]
    Serde(String),
}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(t: T) -> Self {
        Error::Serde(t.to_string())
    }
}

/// Deserialize a struct from an APR table.
pub fn from_apr_table<'a, T>(table: *const ffi::apr_table_t) -> Result<T, Error>
where
    T: Deserialize<'a>,
{
    let mut deserializer = AprTableDeserializer { table, field: None };
    let t = T::deserialize(&mut deserializer)?;
    Ok(t)
}

struct AprTableDeserializer {
    table: *const ffi::apr_table_t,
    field: Option<&'static str>,
}

impl<'de, 'a> Deserializer<'de> for &'a mut AprTableDeserializer {
    type Error = Error;

    fn deserialize_any<V>(self, _: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // log::info!(
        //     "deserialize_any with V = {} and V::Value = {}",
        //     std::any::type_name::<V>(),
        //     std::any::type_name::<V::Value>()
        // );

        Err(Error::NotSupported)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let field = self.field.ok_or(Error::Internal)?;

        let key = CString::new(field).unwrap();
        let value = unsafe { ffi::apr_table_get(self.table, key.as_ptr()) };
        if value.is_null() {
            return Err(Error::NotFound);
        }
        let value = unsafe { CStr::from_ptr(value) }
            .to_str()
            .unwrap()
            .to_string();
        visitor.visit_string(value)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let field = self.field.ok_or(Error::Internal)?;

        let key = CString::new(field).unwrap();
        let value = unsafe { ffi::apr_table_get(self.table, key.as_ptr()) };
        if value.is_null() {
            return Err(Error::NotFound);
        }
        let value = unsafe { CStr::from_ptr(value) }.to_str().unwrap();
        visitor.visit_str(value)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let field = self.field.ok_or(Error::Internal)?;

        let key = CString::new(field).unwrap();
        let value = unsafe { ffi::apr_table_get(self.table, key.as_ptr()) };
        if value.is_null() {
            return Err(Error::NotFound);
        }
        let value = unsafe { CStr::from_ptr(value) }.to_str().unwrap();
        let value = value.parse().map_err(serde::de::Error::custom)?;
        visitor.visit_bool(value)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let field = self.field.ok_or(Error::Internal)?;

        let key = CString::new(field).unwrap();
        let value = unsafe { ffi::apr_table_get(self.table, key.as_ptr()) };
        if value.is_null() {
            return Err(Error::NotFound);
        }
        let value = unsafe { CStr::from_ptr(value) }.to_str().unwrap();
        let value = value.parse().map_err(serde::de::Error::custom)?;
        visitor.visit_u64(value)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let field = self.field.ok_or(Error::Internal)?;

        let key = CString::new(field).unwrap();
        let value = unsafe { ffi::apr_table_get(self.table, key.as_ptr()) };
        if value.is_null() {
            return Err(Error::NotFound);
        }
        let value = unsafe { CStr::from_ptr(value) }.to_str().unwrap();
        let value = value.parse().map_err(serde::de::Error::custom)?;
        visitor.visit_f32(value)
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        struct Access<'b> {
            fields: &'static [&'static str],
            deserializer: &'b mut AprTableDeserializer,
        }

        impl<'de, 'b> SeqAccess<'de> for Access<'b> {
            type Error = Error;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
            where
                T: DeserializeSeed<'de>,
            {
                if let Some((field, fields)) = self.fields.split_first() {
                    self.fields = fields;
                    let mut deserializer = AprTableDeserializer {
                        table: self.deserializer.table,
                        field: Some(field),
                    };
                    match DeserializeSeed::deserialize(seed, &mut deserializer) {
                        Ok(value) => Ok(Some(value)),
                        Err(Error::NotFound) => Ok(None),
                        Err(err) => Err(err),
                    }
                } else {
                    Ok(None)
                }
            }
        }

        visitor.visit_seq(Access {
            fields,
            deserializer: self,
        })
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let field = self.field.ok_or(Error::Internal)?;

        let key = CString::new(field).unwrap();
        let value = unsafe { ffi::apr_table_get(self.table, key.as_ptr()) };
        if value.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    serde::forward_to_deserialize_any! {
            i8 i16 i32 i64 i128
            u8 u16 u32 u128
            f64
            char bytes byte_buf
            unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
    }
}

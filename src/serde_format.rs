use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod datetime_format {
    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%.3fZ";

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(DateTime::parse_from_str(&s, FORMAT)
            .map_err(serde::de::Error::custom)?
            .with_timezone(&Utc))
    }
}

pub mod option_datetime_format {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%.3fZ";

    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(d) = date {
            let s = format!("{}", d.format(FORMAT));
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = Option::<String>::deserialize(deserializer)?;
        if let Some(s) = string {
            Ok(Some(
                DateTime::parse_from_str(&s, FORMAT)
                    .map_err(serde::de::Error::custom)?
                    .with_timezone(&Utc),
            ))
        } else {
            Ok(None)
        }
    }
}

pub mod date_format {
    use chrono::NaiveDate;
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%d";

    pub fn serialize<S>(date: &NaiveDate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<NaiveDate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        NaiveDate::parse_from_str(&s, FORMAT).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
pub struct UtcDatetime(DateTime<Utc>);

impl Serialize for UtcDatetime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let format = "%Y-%m-%dT%H:%M:%S%.3fZ";
        let datetime = self.0;
        let s = format!("{}", datetime.format(format));
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for UtcDatetime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let format = "%Y-%m-%dT%H:%M:%S%.3fZ";
        let s = String::deserialize(deserializer)?;
        Ok(Self(
            DateTime::parse_from_str(&s, format)
                .map_err(serde::de::Error::custom)?
                .with_timezone(&Utc),
        ))
    }
}

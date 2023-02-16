#[cfg(test)]
mod test;

use urlencoding::encode;
use std::iter::Iterator;

pub trait UrlParams
where
    Self: Iterator<Item = (String, String)> + Sized
{
    fn into_url_params(self) -> String {
        self
            .map(|(k, v)|{
                (encode(&k).into_owned(), encode(&v).into_owned())
            })
            .enumerate()
            .map(|(i, (k, v))|{
                let prefix = match i {
                    0 => "?",
                    _ => "&"
                };

                String::new() + prefix + &k + "=" + &v
            })
            .collect()
    }
}

impl<S> UrlParams for S
where S: Iterator<Item = (String, String)> + Sized {}
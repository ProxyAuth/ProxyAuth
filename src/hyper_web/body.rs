//! Corps de réponse servi par hyper.
//!
//! Trois formes seulement, celles dont ProxyAuth a besoin : pas de corps
//! (204/304, `finish()` sur HEAD…), un corps entièrement en mémoire, et un
//! flux paresseux (réponses d'un backend relayées sans être bufferisées).

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body::{Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Erreur d'un flux de corps. `Send + Sync` parce que c'est ce qu'hyper
/// exige pour pouvoir la remonter à la connexion.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + 'static>>;

/// Taille connue d'un corps — même sémantique que `actix_web::body::BodySize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySize {
    /// Aucun corps (pas de `Content-Length` émis).
    None,
    /// Corps de taille connue.
    Sized(u64),
    /// Taille inconnue (flux).
    Stream,
}

pub struct Body {
    inner: Inner,
}

enum Inner {
    None,
    Bytes(Bytes),
    Stream(BodyStream),
}

impl Body {
    /// Pas de corps du tout.
    pub fn none() -> Self {
        Body { inner: Inner::None }
    }

    /// Corps vide mais présent (`Content-Length: 0`).
    pub fn empty() -> Self {
        Body {
            inner: Inner::Bytes(Bytes::new()),
        }
    }

    pub fn from_stream<S, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, E>> + 'static,
        E: Into<BoxError> + 'static,
    {
        Body {
            inner: Inner::Stream(Box::pin(stream.map(|r| r.map_err(Into::into)))),
        }
    }

    pub fn size(&self) -> BodySize {
        match &self.inner {
            Inner::None => BodySize::None,
            Inner::Bytes(b) => BodySize::Sized(b.len() as u64),
            Inner::Stream(_) => BodySize::Stream,
        }
    }

    /// Le contenu s'il est déjà entièrement en mémoire.
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match &self.inner {
            Inner::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Variante d'`actix_web::body::MessageBody::try_into_bytes`.
    pub fn try_into_bytes(self) -> Result<Bytes, Self> {
        match self.inner {
            Inner::Bytes(b) => Ok(b),
            Inner::None => Ok(Bytes::new()),
            other => Err(Body { inner: other }),
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Body::empty()
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Inner::None => f.write_str("Body::None"),
            Inner::Bytes(b) => write!(f, "Body::Bytes({} bytes)", b.len()),
            Inner::Stream(_) => f.write_str("Body::Stream"),
        }
    }
}

macro_rules! body_from {
    ($($t:ty => $conv:expr),* $(,)?) => {
        $(impl From<$t> for Body {
            fn from(v: $t) -> Self {
                Body { inner: Inner::Bytes($conv(v)) }
            }
        })*
    };
}

body_from! {
    Bytes => |b: Bytes| b,
    Vec<u8> => Bytes::from,
    String => Bytes::from,
    &'static str => |s: &'static str| Bytes::from_static(s.as_bytes()),
    &'static [u8] => Bytes::from_static,
    &String => |s: &String| Bytes::copy_from_slice(s.as_bytes()),
    bytes::BytesMut => |b: bytes::BytesMut| b.freeze(),
}

impl From<()> for Body {
    fn from(_: ()) -> Self {
        Body::empty()
    }
}

impl From<std::borrow::Cow<'static, str>> for Body {
    fn from(v: std::borrow::Cow<'static, str>) -> Self {
        match v {
            std::borrow::Cow::Borrowed(s) => s.into(),
            std::borrow::Cow::Owned(s) => s.into(),
        }
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match &mut self.inner {
            Inner::None => Poll::Ready(None),
            Inner::Bytes(b) => {
                if b.is_empty() {
                    Poll::Ready(None)
                } else {
                    let data = std::mem::take(b);
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
            }
            Inner::Stream(s) => match s.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Inner::None => true,
            Inner::Bytes(b) => b.is_empty(),
            Inner::Stream(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Inner::None => SizeHint::with_exact(0),
            Inner::Bytes(b) => SizeHint::with_exact(b.len() as u64),
            Inner::Stream(_) => SizeHint::default(),
        }
    }
}

/// Lit un corps complet en mémoire (équivalent de `actix_web::body::to_bytes`).
pub async fn to_bytes(body: Body) -> Result<Bytes, BoxError> {
    match body.inner {
        Inner::None => Ok(Bytes::new()),
        Inner::Bytes(b) => Ok(b),
        Inner::Stream(mut s) => {
            let mut buf = bytes::BytesMut::new();
            while let Some(chunk) = s.next().await {
                buf.extend_from_slice(&chunk?);
            }
            Ok(buf.freeze())
        }
    }
}

/// Comme [`to_bytes`] mais refuse au-delà de `limit` octets.
pub async fn to_bytes_limited(body: Body, limit: usize) -> Result<Result<Bytes, BoxError>, ()> {
    match body.inner {
        Inner::None => Ok(Ok(Bytes::new())),
        Inner::Bytes(b) => {
            if b.len() > limit {
                Err(())
            } else {
                Ok(Ok(b))
            }
        }
        Inner::Stream(mut s) => {
            let mut buf = bytes::BytesMut::new();
            while let Some(chunk) = s.next().await {
                match chunk {
                    Ok(c) => {
                        if buf.len() + c.len() > limit {
                            return Err(());
                        }
                        buf.extend_from_slice(&c);
                    }
                    Err(e) => return Ok(Err(e)),
                }
            }
            Ok(Ok(buf.freeze()))
        }
    }
}

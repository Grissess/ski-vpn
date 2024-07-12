use crate::error;

use std::path::Path;
use std::net::Ipv4Addr;
use std::pin::Pin;

use sqlite::{Connection, Statement, Value, State};

use ski::sym::Key;

struct ExecIter<'l, 's> {
    stmt: &'l mut Statement<'s>,
    count: usize,
}

impl<'l, 's> Iterator for ExecIter<'l, 's> {
    type Item = error::Result<Vec<Value>>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.stmt.next() {
            Err(e) => Some(Err(error::Error::from(e))),
            Ok(State::Done) => None,
            Ok(State::Row) => {
                let mut vec = vec![Value::Null; self.count];
                for i in 0..self.count {
                    vec[i] = match self.stmt.read::<Value, _>(i) {
                        Err(e) => return Some(Err(error::Error::from(e))),
                        Ok(v) => v,
                    };
                }
                Some(Ok(vec))
            },
        }
    }
}

impl<'l, 's> Drop for ExecIter<'l, 's> {
    fn drop(&mut self) {
        // Drain the iterator, if need be
        while let Some(_) = self.next() {}
        self.stmt.reset().unwrap()
    }
}

fn execute_with<'l, 's, 'v>(st: &'l mut Statement<'s>, v: &'v [Value]) -> error::Result<ExecIter<'l, 's>> {
    for (idx, v) in v.iter().enumerate() {
        st.bind((idx + 1, v))?;
    }
    let count = st.column_count();
    Ok(ExecIter {
        stmt: st,
        count,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl Prefix {
    pub fn from_addr_mask(addr: Ipv4Addr, mask: Ipv4Addr) -> Self {
        Self { addr, mask }
    }

    pub fn from_addr_bits(addr: Ipv4Addr, bits: u8) -> error::Result<Self> {
        if bits <= 32 {
            Ok(Self {
                addr,
                mask: (!((1u32 << (32 - bits)) - 1)).into(),
            })
        } else {
            Err(error::ErrorKind::InvalidBits(bits).into())
        }
    }

    pub fn bits(self) -> u8 {
        u32::from(self.mask).leading_ones() as u8
    }

    pub fn matches(self, a: Ipv4Addr) -> bool {
        u32::from(a) & u32::from(self.mask) == u32::from(self.addr)
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub prefix: Prefix,
    pub key: Option<Key>,
    pub dest: Ipv4Addr,
}

pub struct Table {
// SAFETY: these private fields have an inaccurate and untenable lifetime, transmuted in the
// constructor. This is _only_ safe as long as these fields _never_ leak to the public API, as any
// user (other than us) which can take a reference to them can violate lifetime coherence.
// The order of fields is chosen so that they are dropped first, as required.
    st_ins: Option<Statement<'static>>,
    st_all: Option<Statement<'static>>,
    con: Connection,
}

impl Table {
    pub fn new<P: AsRef<Path>>(path: P) -> error::Result<Pin<Box<Self>>> {
        let con = sqlite::open(path)?;
        con.execute("
            CREATE TABLE IF NOT EXISTS routes (
                address INTEGER NOT NULL,
                mask INTEGER NOT NULL,
                key BLOB,
                destination INTEGER NOT NULL,
                PRIMARY KEY (address ASC, mask DESC) ON CONFLICT REPLACE
            );
        ")?;
        let mut tbl = Box::pin(Table {
            con,
            st_ins: None,
            st_all: None,
        });
        unsafe {
            // SAFETY: these Options are not structurally pinned, nor projected.
            let r = Pin::as_mut(&mut tbl);
            let this = Pin::get_unchecked_mut(r);
            this.st_ins = Some(std::mem::transmute(
                this.con.prepare("\
                    INSERT INTO routes (address, mask, key, destination) VALUES (?, ?, ?, ?);\
                ")?
            ));
            this.st_all = Some(std::mem::transmute(
                this.con.prepare("\
                    SELECT (address, mask, key, destination) FROM routes;\
                ")?
            ));
        }
        Ok(tbl)
    }

    pub fn insert(&mut self, ent: &Entry) -> error::Result<()> {
        for res in execute_with(self.st_ins.as_mut().unwrap(),
            &[
                 Value::Integer(u32::from(ent.prefix.addr) as i64),
                 Value::Integer(u32::from(ent.prefix.mask) as i64),
                 if let Some(k) = &ent.key {
                     Value::Binary(k.bytes.to_vec())
                 } else {
                     Value::Null
                 },
                 Value::Integer(u32::from(ent.dest) as i64),
            ],
        )? { let _ = res?; }
        Ok(())
    }

    pub fn find(&mut self, to: Ipv4Addr) -> error::Result<Entry> {
        use error::ErrorKind::InvalidDataType;

        for maybe_row in execute_with(self.st_all.as_mut().unwrap(), &[])? {
            let row = maybe_row?;
            let pfx = Prefix::from_addr_mask(
                Ipv4Addr::from(row[0].try_into::<i64>().map_err(|_| InvalidDataType)? as u32),
                Ipv4Addr::from(row[1].try_into::<i64>().map_err(|_| InvalidDataType)? as u32),
            );
            if pfx.matches(to) {
                return Ok(Entry {
                    prefix: pfx,
                    key: if row[2].kind() == sqlite::Type::Null {
                        None
                    } else {
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(row[2].try_into::<&[u8]>().map_err(|_| InvalidDataType)?);
                        Some(Key { bytes })
                    },
                    dest: (row[3].try_into::<i64>().map_err(|_| InvalidDataType)? as u32).into(),
                })
            }
        }
        Err(error::ErrorKind::NoRoute(to).into())
    }
}

#[macro_use]
extern crate nom;
extern crate byteorder;

use std::str;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt};
use nom::{IResult, be_u8};

#[derive(Debug)]
enum Record<'a> {
    Simple { offset: &'a [u8], size: u16, data: &'a [u8] },
    Rle { offset: &'a [u8], times: u16, data: u8 }
}

fn main() {
    let mut f = File::open("/Users/robinm/Downloads/SweetHome.ips").expect("File not found");
    let mut buf: Vec<u8> = vec![];
    f.read_to_end(&mut buf).unwrap();
    println!("{:?}", read_ips(&buf));

}

fn take_int(input: &[u8], length: u8) -> IResult<&[u8], u16> {
    do_parse!(input, number: map!(take!(length), bytes_to_int) >> (number))
}

fn bytes_to_int(input: &[u8]) -> u16 {
    let mut rdr = Cursor::new(input);
    rdr.read_u16::<BigEndian>().expect("Failed to parse chunk size")
}

named!(read_ips<&[u8], Vec<Record>>,
    do_parse!(
                    tag!("PATCH")               >>
        records:    many1!(complete!(record))   >>
                    tag!("EOF")                 >>

        (records)
    )
);

named!(record<&[u8], Record>,
    alt!(record_rle | record_simple)
);

named!(record_simple<&[u8], Record>,
    do_parse!(
        offset: take!(3)            >>
        size:   apply!(take_int, 2) >>
        data:   take!(size)         >>

        (Record::Simple { offset: offset, size: size, data: data })
    )
);

named!(record_rle<&[u8], Record>,
    do_parse!(
        offset: take!(3)            >>
                tag!([00u8, 00u8])  >>
        times:  apply!(take_int, 2) >>
        data:   be_u8               >>

        (Record::Rle { offset: offset, times: times, data: data })
    )
);

use std::{env, fs, time::Instant};

use pcap_file::{pcap::PcapParser, pcapng::PcapNgParser};
use pcap_parser::{PcapError, create_reader};

fn pcap_file_count(bytes: &[u8], pcapng: bool) -> Result<usize, String> {
    if pcapng {
        let (mut remaining, mut parser) =
            PcapNgParser::new(bytes).map_err(|error| error.to_string())?;
        let mut count = 0;
        while !remaining.is_empty() {
            let (next, _) = parser
                .next_block(remaining)
                .map_err(|error| error.to_string())?;
            if next.len() == remaining.len() {
                return Err("parser did not consume input".into());
            }
            remaining = next;
            count += 1;
        }
        Ok(count)
    } else {
        let (mut remaining, parser) = PcapParser::new(bytes).map_err(|error| error.to_string())?;
        let mut count = 0;
        while !remaining.is_empty() {
            let (next, _) = parser
                .next_packet(remaining)
                .map_err(|error| error.to_string())?;
            if next.len() == remaining.len() {
                return Err("parser did not consume input".into());
            }
            remaining = next;
            count += 1;
        }
        Ok(count)
    }
}

fn pcap_parser_count(bytes: &[u8]) -> Result<usize, String> {
    let mut reader =
        create_reader(65_536, std::io::Cursor::new(bytes)).map_err(|error| error.to_string())?;
    let mut count: usize = 0;
    loop {
        match reader.next() {
            Ok((offset, _)) => {
                reader.consume(offset);
                count += 1;
            }
            // The generic reader emits the capture header/section header as its first block.
            Err(PcapError::Eof) => return Ok(count.saturating_sub(1)),
            Err(PcapError::Incomplete(_)) => reader.refill().map_err(|error| error.to_string())?,
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let format = args.next().expect("format: pcap or pcapng");
    let path = args.next().expect("input path");
    let bytes = fs::read(path).expect("read input");
    let pcapng = format == "pcapng";

    let started = Instant::now();
    let first = pcap_file_count(&bytes, pcapng);
    let first_elapsed = started.elapsed();
    let started = Instant::now();
    let second = pcap_parser_count(&bytes);
    let second_elapsed = started.elapsed();

    println!(
        "pcap-file: {first:?}; elapsed_us={}",
        first_elapsed.as_micros()
    );
    println!(
        "pcap-parser: {second:?}; elapsed_us={}",
        second_elapsed.as_micros()
    );
}

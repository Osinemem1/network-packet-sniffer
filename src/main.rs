use pcap::{Capture, Device};
use std::fmt::Write;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    println!("📡 NetSniff - Packet Sniffer");
    println!("============================");

  let device = Device::list()?
  .into_iter()
  .find(|d| !d.name.contains("lo"))
  .or_else(|| Device::list().ok().and_then(|mut d| d.pop()))
  .ok_or("No available network device found")?;

  println!("Using device: {}", device.name);

 let mut cap = Capture::from_device(device)?
    .promisc(true)
    .timeout(1000)
    .open()?;

println!("\nStarting capture. Press Ctrl+C to stop.\n");
println!("{:<18} {:<18} {:<18} {:<6}", "Source MAC", "Destination MAC", "Protocol", "Length");
println!("{:-<60}", "");


while let Ok(packet) = cap.next_packet() {
    let length = packet.header.len;

    if packet.data.len() >= 14 {

        let (src_mac, dst_mac, ether_type) = parse_ethernet_frame(&packet.data);
        println!("{:<18} {:<18} {:<18} {:<6}", src_mac, dst_mac, format!("0x{0:04X}", ether_type), length);
 } else {
        println!("{:<18} {:<18} {:<8} {:<6}", "Malformed", "Packet", "N/A", length);
 }
}
Ok(())
}
fn parse_ethernet_frame(data: &[u8]) -> (String, String, u16) {
    let dst_mac = format_mac_address(&data[0..6]);

    let src_mac = format_mac_address(&data[6..12]);

    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    (src_mac, dst_mac, ether_type)
}

fn format_mac_address(byts: &[u8]) -> String {
    let mut mac = String::new();
    for (i, byte) in byts.iter().enumerate() {
        if i > 0 {
            write!(&mut mac, ":").unwrap();
        }
        write!(&mut mac, "{:02x}", byte).unwrap();
    }
    mac
}
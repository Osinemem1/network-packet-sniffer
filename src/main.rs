use pcap::{Capture, Device};
use std::fmt::Write;
use std::net::Ipv4Addr;
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
println!("{:<18} {:<18} {:<15} {:<15} {:<6}", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Length");
println!("{:-<80}", "");


while let Ok(packet) = cap.next_packet() {
    let length = packet.header.len;

    if packet.data.len() >= 14 {

        let (src_mac, dst_mac, ether_type) = parse_ethernet_frame(&packet.data);


    if ether_type == 0x0800 && packet.data.len() >= 34 {

        if let Some((src_ip, dst_ip)) = parse_ipv4_header(&packet.data[14..]){
            println!("{:<18} {:<18} {:<15} {:<15}  {:<6}", src_mac, dst_mac, src_ip, dst_ip, length);
        } else {
        println!("{:<18} {:<18} {:<15} {:<15} {:<6}", src_mac, dst_mac ,"Malformed", "IP", length);
 }

}else{
     println!("{:<18} {:<18} {:<15} {:<15} {:<6}", src_mac, dst_mac ,"Non-IPV4", "Packet", length);
 }
}else{
     println!("{:<18} {:<18} {:<15} {:<15} {:<6}", "Malformed", "Packet", "N/A", "N/A", length);
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
fn parse_ipv4_header(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 20 {
        return None;
    }

    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);

     let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

     Some((src_ip.to_string(), dst_ip.to_string()))
}

fn format_mac_address(bytes: &[u8]) -> String {
    let mut mac = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            write!(&mut mac, ":").unwrap();
        }
        write!(&mut mac, "{:02x}", byte).unwrap();
    }
    mac
}
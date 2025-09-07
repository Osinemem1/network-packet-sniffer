use pcap::Device;

fn main() {
    println!("📡 NetSniff - Packet Sniffer");
    println!("============================");

  let device = Device::list()
  .expect("Error listing devices")
  .into_iter()
  .find(|d| !d.name.contains("lo"))

  .or_else(|| Device::list().ok().and_then(|mut d| d.pop()))
  .expect("No available network devices found");
  println!("Using devices: {}", device.name);

  println!("\nAvailable network devices:");
  for device in Device::list().expect("Error listing devices") {
    println!("- {}", device.name);
  }
}

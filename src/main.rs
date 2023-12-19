fn main() {
  let result = openidconnect_prototype::run_prototype();
  if let Err(e) = result {
    println!("{}", e);
  }
}

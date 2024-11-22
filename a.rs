fn main() {
  let mut v = vec![1, 2, 3];

  let mut buffer = String::new();
  std::io::stdin().read_line(&mut buffer).unwrap();

  if buffer.starts_with("123") {
      unsafe {
        v.set_len(10);
      }

      v[4] = 123;
      println!("{:?}", v);
  } else {
      println!("{:?}", buffer);
  }
}

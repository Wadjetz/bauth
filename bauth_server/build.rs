// `sqlx::migrate!()` embeds the migrations at compile time: rebuild when one is added or edited.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}

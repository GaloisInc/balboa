#[inline(never)]
fn do_the_test() {
    balboa_injection::stacks::run_on_fresh_stack(|| ());
}

fn main() {
    do_the_test();
}

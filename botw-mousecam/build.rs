use cc::Build;
use std::env;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut build = Build::new();
        build.file("src/interceptor.asm");
        build.compile("interceptor");

        // Add resource file
        let res = winres::WindowsResource::new();
        res.compile().unwrap();
    }
}

use std::fs::File;

fn main() -> std::io::Result<()> {
    let mut stdout = std::io::stdout();

    for path in std::env::args_os().skip(1) {
        let mut file = File::open(path)?;
        std::io::copy(&mut file, &mut stdout)?;
    }

    Ok(())
}

//! Renders `porthole.1`, the per-subcommand man pages and the bash, zsh and
//! fish completions from the same clap definition `main` parses with.
//!
//! `src/cli_def.rs` is `include!`d rather than imported: a build script
//! cannot depend on a library target of its own package, and `porthole-cli`
//! is a binary. That file is kept free of `porthole_core` types so this
//! script needs only clap as a build dependency.
//!
//! Output goes to `<target>/<profile>/assets/`, next to the binaries the
//! same `cargo build` produces, because `OUT_DIR` is a hashed path no
//! Makefile can name. `make install` reads exactly those paths and fails if
//! one is missing.

use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use clap::{Command, CommandFactory};
use clap_complete::Shell;

include!("src/cli_def.rs");

/// `<target>/<profile>/assets`, derived from `OUT_DIR`
/// (`<target>/<profile>/build/<pkg>-<hash>/out`).
///
/// Panics rather than guessing if `OUT_DIR` is not that shape: a build that
/// silently wrote the man page somewhere no Makefile looks would surface as
/// a package missing its documentation, long after the build that caused it.
fn assets_dir() -> PathBuf {
    if let Some(explicit) = env::var_os("PORTHOLE_ASSET_DIR") {
        return PathBuf::from(explicit);
    }
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set for a build script"));
    let profile_dir = out_dir.ancestors().nth(3).unwrap_or_else(|| {
        panic!(
            "OUT_DIR has fewer than three parents: {}",
            out_dir.display()
        )
    });
    let shaped = out_dir.file_name().is_some_and(|n| n == "out")
        && out_dir
            .ancestors()
            .nth(2)
            .and_then(Path::file_name)
            .is_some_and(|n| n == "build");
    assert!(
        shaped,
        "OUT_DIR is not <target>/<profile>/build/<pkg>-<hash>/out: {}. \
         Set PORTHOLE_ASSET_DIR to say where the man page and completions \
         should go.",
        out_dir.display()
    );
    profile_dir.join("assets")
}

/// Renders `cmd` and every subcommand below it, naming each page after the
/// path that reaches it: `porthole-devices-rm.1` for `porthole devices rm`.
///
/// Recursive because clap_mangen's SUBCOMMANDS section cross-references each
/// child as `porthole-devices-list(1)`; a page that points at pages nobody
/// installed is a broken reference in every package at once. `version` on
/// each page, or the child pages carry an empty footer where the top-level
/// one carries "porthole <version>".
fn render_tree(cmd: &Command, name: &str, version: &'static str, dir: &Path) -> io::Result<()> {
    // `disable_help_subcommand` per page, not once at the root: clap does not
    // propagate it, so without it here every page with subcommands renders a
    // `porthole-devices-help(1)` cross-reference of its own. What that
    // subcommand prints is what `--help` prints, and OPTIONS documents that.
    // The completions are generated from the command with `help` left in, so
    // `porthole help <TAB>` still completes.
    let page = cmd
        .clone()
        .name(name.to_string())
        .version(version)
        .disable_help_subcommand(true);
    let mut out = Vec::new();
    clap_mangen::Man::new(page).render(&mut out)?;
    fs::write(dir.join(format!("{name}.1")), out)?;

    for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
        render_tree(sub, &format!("{name}-{}", sub.get_name()), version, dir)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/cli_def.rs");
    println!("cargo:rerun-if-env-changed=PORTHOLE_ASSET_DIR");

    let assets = assets_dir();
    let man_dir = assets.join("man");
    let comp_dir = assets.join("completions");
    // Emptied, not merely created: a subcommand that has been removed leaves
    // a page behind otherwise, and `make install` would keep shipping it.
    for dir in [&man_dir, &comp_dir] {
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        fs::create_dir_all(dir)?;
    }

    let version = env!("CARGO_PKG_VERSION");
    render_tree(&Cli::command(), "porthole", version, &man_dir)?;

    let mut cmd = Cli::command().version(version);
    for (shell, file) in [
        (Shell::Bash, "porthole.bash"),
        (Shell::Zsh, "_porthole"),
        (Shell::Fish, "porthole.fish"),
    ] {
        let mut out = File::create(comp_dir.join(file))?;
        clap_complete::generate(shell, &mut cmd, "porthole", &mut out);
    }

    Ok(())
}

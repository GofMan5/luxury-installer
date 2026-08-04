use std::{fs, process::Command};

use tempfile::tempdir;

#[test]
fn every_public_command_has_non_mutating_subcommand_help() {
    let temp = tempdir().unwrap();
    for command in [
        "stdio",
        "init",
        "build",
        "publisher-key-id",
        "prepare-rotation",
        "inspect",
        "prepare-install",
        "install",
        "uninstall",
        "launch",
        "help",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_luxury"))
            .args([command, "--help"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{command}: {output:?}");
        assert!(
            output.stdout.is_empty(),
            "{command} wrote protocol/data stdout"
        );
        let help = String::from_utf8(output.stderr).unwrap();
        assert!(help.contains("Usage:"), "{command}: {help}");
        assert!(help.contains(command), "{command}: {help}");
    }
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn public_ai_docs_cover_the_live_cli_and_jsonl_methods() {
    let binary = env!("CARGO_BIN_EXE_luxury");
    let output = Command::new(binary).arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stderr).unwrap();
    let commands = help
        .lines()
        .filter_map(|line| line.trim().strip_prefix(binary))
        .filter_map(|usage| usage.split_whitespace().next())
        .collect::<Vec<_>>();
    assert!(
        !commands.is_empty(),
        "global help contained no commands: {help}"
    );

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().unwrap().parent().unwrap();
    let llms = fs::read_to_string(root.join("llms.txt")).unwrap();
    let reference =
        fs::read_to_string(root.join("skills/luxury-installer-cli/references/cli.md")).unwrap();
    for command in commands {
        let needle = format!("luxury {command}");
        assert!(llms.contains(&needle), "llms.txt misses `{needle}`");
        assert!(reference.contains(&needle), "CLI skill misses `{needle}`");
    }

    let stdio = fs::read_to_string(manifest.join("src/stdio.rs")).unwrap();
    let protocol_version = luxury_spec::JSONL_PROTOCOL_VERSION.to_string();
    let methods = stdio
        .split("fn handle_request")
        .nth(1)
        .unwrap()
        .split("fn defaults")
        .next()
        .unwrap()
        .lines()
        .filter_map(|line| line.trim().strip_prefix('"'))
        .filter_map(|line| line.split_once('"'))
        .filter_map(|(method, tail)| tail.trim_start().starts_with("=>").then_some(method))
        .collect::<Vec<_>>();
    assert!(!methods.is_empty());
    let ai_guide = fs::read_to_string(root.join("docs/ai-build.md")).unwrap();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    for (name, document) in [
        ("README.md", readme.as_str()),
        ("llms.txt", llms.as_str()),
        ("docs/ai-build.md", ai_guide.as_str()),
        ("CLI skill", reference.as_str()),
    ] {
        assert!(
            document.contains(&format!("JSONL v{protocol_version}"))
                || document.contains(&format!("JSONL protocol v{protocol_version}")),
            "{name} misses JSONL v{protocol_version}"
        );
    }
    let tauri_protocol =
        fs::read_to_string(root.join("apps/luxury-installer/src-tauri/src/backend/protocol.rs"))
            .unwrap();
    assert!(
        tauri_protocol
            .contains("PROTOCOL_VERSION: u64 = luxury_spec::JSONL_PROTOCOL_VERSION as u64;"),
        "Tauri and luxury stdio protocol versions differ"
    );
    for method in methods {
        for (name, document) in [
            ("llms.txt", llms.as_str()),
            ("docs/ai-build.md", ai_guide.as_str()),
            ("CLI skill", reference.as_str()),
        ] {
            assert!(document.contains(method), "{name} misses JSONL `{method}`");
        }
    }

    let tauri_shell =
        fs::read_to_string(root.join("apps/luxury-installer/src-tauri/src/lib.rs")).unwrap();
    for flag in ["--unattended-install", "--unattended-uninstall"] {
        assert!(tauri_shell.contains(flag), "Tauri Setup misses `{flag}`");
        for (name, document) in [
            ("README.md", readme.as_str()),
            ("llms.txt", llms.as_str()),
            ("docs/ai-build.md", ai_guide.as_str()),
            ("CLI skill", reference.as_str()),
        ] {
            assert!(document.contains(flag), "{name} misses Setup `{flag}`");
        }
    }

    for (name, document) in [
        ("README.md", readme),
        (
            "CONTRIBUTING.md",
            fs::read_to_string(root.join("CONTRIBUTING.md")).unwrap(),
        ),
        ("docs/ai-build.md", ai_guide),
        ("llms.txt", llms),
    ] {
        assert!(
            !document.contains("AGENTS.md"),
            "{name} links internal AGENTS.md"
        );
        assert!(
            !document.contains("MEMORY.md"),
            "{name} links internal MEMORY.md"
        );
    }
}

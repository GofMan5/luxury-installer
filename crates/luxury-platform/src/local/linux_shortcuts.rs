use std::{
    fs, io,
    path::{Component, Path, PathBuf},
};

use luxury_spec::{PackageId, ShortcutPolicy};

const MAX_USER_DIRS_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LinuxShortcutEnvironment {
    pub(super) home: PathBuf,
    pub(super) xdg_data_home: Option<PathBuf>,
    pub(super) xdg_config_home: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LinuxShortcutRoots {
    pub(super) application_menu: Option<PathBuf>,
    pub(super) desktop: Option<PathBuf>,
}

pub(super) fn resolve_linux_shortcut_roots(
    environment: &LinuxShortcutEnvironment,
    shortcuts: ShortcutPolicy,
) -> io::Result<LinuxShortcutRoots> {
    let home = existing_real_directory("HOME", &environment.home)?;
    let application_menu = match (shortcuts.application_menu, &environment.xdg_data_home) {
        (true, Some(path)) => {
            Some(existing_real_directory("XDG_DATA_HOME", path)?.join("applications"))
        }
        (true, None) => Some(
            existing_real_directory("default XDG data home", &home.join(".local/share"))?
                .join("applications"),
        ),
        (false, _) => None,
    };
    let desktop = if shortcuts.desktop {
        let config_home = match &environment.xdg_config_home {
            Some(path) => absolute_normalized("XDG_CONFIG_HOME", path)?,
            None => home.join(".config"),
        };
        read_desktop_root(&config_home.join("user-dirs.dirs"), &home)?
    } else {
        None
    };

    Ok(LinuxShortcutRoots {
        application_menu,
        desktop,
    })
}

pub(super) fn desktop_entry_path(root: &Path, package_id: &PackageId) -> PathBuf {
    root.join(format!("{package_id}.desktop"))
}

pub(super) fn desktop_entry_bytes(
    authenticated_name: &str,
    entrypoint: &Path,
    install_root: &Path,
) -> io::Result<Vec<u8>> {
    let entrypoint = absolute_normalized("shortcut entrypoint", entrypoint)?;
    let install_root = absolute_normalized("shortcut install root", install_root)?;
    let name = escape_desktop_string(authenticated_name)?;
    let exec = quote_exec_token(&entrypoint)?;
    let path = escape_desktop_string(&path_text("shortcut install root", &install_root)?)?;

    Ok(format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName={name}\nExec={exec}\nPath={path}\nTerminal=false\n"
    )
    .into_bytes())
}

fn read_desktop_root(config: &Path, home: &Path) -> io::Result<Option<PathBuf>> {
    let source = match bounded_read(config, MAX_USER_DIRS_BYTES) {
        Ok(source) => source,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut value: Option<Option<PathBuf>> = None;
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, encoded)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "XDG_DESKTOP_DIR" {
            continue;
        }
        if value.is_some() {
            return Err(invalid_data(
                "user-dirs.dirs contains duplicate XDG_DESKTOP_DIR",
            ));
        }
        value = Some(parse_user_dir_value(encoded.trim(), home)?);
    }
    match value.flatten() {
        Some(path) => existing_real_directory("XDG_DESKTOP_DIR", &path).map(Some),
        None => Ok(None),
    }
}

fn parse_user_dir_value(encoded: &str, home: &Path) -> io::Result<Option<PathBuf>> {
    let Some(inner) = encoded
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(invalid_data("XDG_DESKTOP_DIR must be one quoted string"));
    };
    let mut decoded = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                let escaped = characters
                    .next()
                    .ok_or_else(|| invalid_data("XDG_DESKTOP_DIR has a trailing escape"))?;
                match escaped {
                    '\\' | '"' | '$' | '`' => decoded.push(escaped),
                    _ => return Err(invalid_data("XDG_DESKTOP_DIR has an unsupported escape")),
                }
            }
            '"' | '\0' | '\n' | '\r' => {
                return Err(invalid_data(
                    "XDG_DESKTOP_DIR contains an invalid character",
                ));
            }
            _ => decoded.push(character),
        }
    }

    if decoded == "$HOME/" {
        // xdg-user-dirs uses the home directory sentinel to disable a user directory.
        return Ok(None);
    }
    let path = if decoded == "$HOME" {
        home.to_path_buf()
    } else if let Some(relative) = decoded.strip_prefix("$HOME/") {
        if relative.is_empty() {
            return Err(invalid_data("XDG_DESKTOP_DIR has an empty HOME suffix"));
        }
        home.join(relative)
    } else {
        PathBuf::from(decoded)
    };
    absolute_normalized("XDG_DESKTOP_DIR", &path).map(Some)
}

fn bounded_read(path: &Path, max_bytes: u64) -> io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data("user-dirs.dirs must be a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(invalid_data("user-dirs.dirs exceeds 64 KiB"));
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > max_bytes {
        return Err(invalid_data("user-dirs.dirs exceeds 64 KiB"));
    }
    String::from_utf8(bytes).map_err(|_| invalid_data("user-dirs.dirs is not UTF-8"))
}

fn existing_real_directory(label: &str, path: &Path) -> io::Result<PathBuf> {
    let normalized = absolute_normalized(label, path)?;
    let metadata = fs::symlink_metadata(&normalized).map_err(|error| {
        io::Error::new(error.kind(), format!("{label} is unavailable: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_input(format!("{label} must be a real directory")));
    }
    Ok(normalized)
}

fn absolute_normalized(label: &str, path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid_input(format!("{label} must be absolute")));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(value) => normalized.push(value),
            _ => {
                return Err(invalid_input(format!(
                    "{label} contains an invalid component"
                )));
            }
        }
    }
    Ok(normalized)
}

fn escape_desktop_string(value: &str) -> io::Result<String> {
    if value.is_empty() || value.chars().any(is_bidi_control) {
        return Err(invalid_input(
            "desktop-entry string is empty or contains bidi controls",
        ));
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            '\r' | '\0' => {
                return Err(invalid_input(
                    "desktop-entry string contains an invalid control",
                ));
            }
            character if character.is_control() => {
                return Err(invalid_input(
                    "desktop-entry string contains an invalid control",
                ));
            }
            _ => escaped.push(character),
        }
    }
    Ok(escaped)
}

fn quote_exec_token(path: &Path) -> io::Result<String> {
    let value = path_text("shortcut entrypoint", path)?;
    if value.chars().any(|character| {
        character == '='
            || character == '%'
            || character == '\0'
            || character.is_control()
            || is_bidi_control(character)
    }) {
        return Err(invalid_input(
            "shortcut entrypoint contains `=`, `%`, a control, or a bidi character",
        ));
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\\\\\"),
            // The Desktop Entry string layer turns `\\` into one slash, then the
            // Exec quoting layer consumes that slash to preserve the literal quote.
            '"' => {
                quoted.push_str("\\\\");
                quoted.push('"');
            }
            '`' | '$' => {
                quoted.push_str("\\\\");
                quoted.push(character);
            }
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn path_text(label: &str, path: &Path) -> io::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_input(format!("{label} is not UTF-8")))
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::tempdir;

    use super::*;

    fn test_environment(root: &Path) -> LinuxShortcutEnvironment {
        let home = root.join("home");
        let data = root.join("data");
        let config = root.join("config");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&data).unwrap();
        fs::create_dir_all(&config).unwrap();
        LinuxShortcutEnvironment {
            home,
            xdg_data_home: Some(data),
            xdg_config_home: Some(config),
        }
    }

    #[test]
    fn codec_is_canonical_and_treats_exec_as_one_literal_token() {
        let entrypoint = Path::new("/opt/Luxury App/bin/quo\"te\\cash$`100.bin");
        let bytes = desktop_entry_bytes("Luxury \\ Demo", entrypoint, Path::new("/opt/Luxury App"))
            .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                "[Desktop Entry]\n",
                "Type=Application\n",
                "Version=1.0\n",
                "Name=Luxury \\\\ Demo\n",
                "Exec=\"/opt/Luxury App/bin/quo\\\\\"te\\\\\\\\cash\\\\$\\\\`100.bin\"\n",
                "Path=/opt/Luxury App\n",
                "Terminal=false\n",
            )
        );
        assert!(
            !String::from_utf8_lossy(
                &desktop_entry_bytes(
                    "\u{041f}\u{0440}\u{0438}\u{043b}\u{043e}\u{0436}\u{0435}\u{043d}\u{0438}\u{0435}",
                    Path::new("/opt/\u{043f}\u{0440}\u{0438}\u{043b}\u{043e}\u{0436}\u{0435}\u{043d}\u{0438}\u{0435}"),
                    Path::new("/opt"),
                )
                .unwrap()
            )
            .contains("Icon=")
        );
    }

    #[test]
    fn codec_rejects_newlines_controls_bidi_and_relative_paths() {
        for name in ["line\nbreak", "bad\u{202e}name"] {
            assert!(desktop_entry_bytes(name, Path::new("/opt/app"), Path::new("/opt")).is_err());
        }
        for entrypoint in [Path::new("relative/app"), Path::new("/opt/line\nbreak")] {
            assert!(desktop_entry_bytes("Demo", entrypoint, Path::new("/opt")).is_err());
        }
        assert!(
            desktop_entry_bytes("Demo", Path::new("/opt/bad=name"), Path::new("/opt")).is_err()
        );
        assert!(
            desktop_entry_bytes("Demo", Path::new("/opt/bad%name"), Path::new("/opt")).is_err()
        );
        assert!(desktop_entry_bytes("Demo", Path::new("/opt/app"), Path::new("relative")).is_err());
    }

    #[test]
    fn exec_two_layer_unescape_round_trips_one_exact_token() {
        let entrypoint = "/opt/Luxury App/bin/quo\"te\\cash$`100.bin";
        let encoded = quote_exec_token(Path::new(entrypoint)).unwrap();
        assert_eq!(parse_exec_token_for_test(&encoded).unwrap(), entrypoint);
    }

    #[test]
    fn resolves_localized_desktop_from_escaped_home_value() {
        let temp = tempdir().unwrap();
        let environment = test_environment(temp.path());
        let desktop = environment.home.join(concat!(
            "\u{0420}\u{0430}\u{0431}\u{043e}\u{0447}\u{0438}\u{0439} ",
            "\u{0441}\u{0442}\u{043e}\u{043b} \"Local\""
        ));
        fs::create_dir(&desktop).unwrap();
        fs::write(
            environment
                .xdg_config_home
                .as_ref()
                .unwrap()
                .join("user-dirs.dirs"),
            concat!(
                "# generated\nXDG_DOWNLOAD_DIR=\"$HOME/",
                "\u{0417}\u{0430}\u{0433}\u{0440}\u{0443}\u{0437}\u{043a}\u{0438}\"\n",
                "XDG_DESKTOP_DIR=\"$HOME/",
                "\u{0420}\u{0430}\u{0431}\u{043e}\u{0447}\u{0438}\u{0439} ",
                "\u{0441}\u{0442}\u{043e}\u{043b} \\\"Local\\\"\"\n",
            ),
        )
        .unwrap();

        let roots = resolve_linux_shortcut_roots(
            &environment,
            ShortcutPolicy {
                application_menu: true,
                desktop: true,
            },
        )
        .unwrap();
        assert_eq!(
            roots.application_menu.as_deref(),
            Some(
                environment
                    .xdg_data_home
                    .as_ref()
                    .unwrap()
                    .join("applications")
                    .as_path()
            )
        );
        assert_eq!(roots.desktop.as_deref(), Some(desktop.as_path()));
    }

    #[test]
    fn missing_desktop_configuration_is_not_guessed() {
        let temp = tempdir().unwrap();
        let environment = test_environment(temp.path());
        let roots = resolve_linux_shortcut_roots(
            &environment,
            ShortcutPolicy {
                application_menu: false,
                desktop: true,
            },
        )
        .unwrap();
        assert_eq!(roots.desktop, None);
        assert!(!environment.home.join("Desktop").exists());
    }

    #[test]
    fn menu_only_does_not_parse_or_require_desktop_state() {
        let temp = tempdir().unwrap();
        let mut environment = test_environment(temp.path());
        let config = environment.xdg_config_home.as_ref().unwrap();
        fs::write(
            config.join("user-dirs.dirs"),
            vec![b'x'; MAX_USER_DIRS_BYTES as usize + 1],
        )
        .unwrap();
        environment.xdg_config_home = Some(PathBuf::from("relative-ignored"));

        let roots = resolve_linux_shortcut_roots(
            &environment,
            ShortcutPolicy {
                application_menu: true,
                desktop: false,
            },
        )
        .unwrap();
        assert!(roots.application_menu.is_some());
        assert_eq!(roots.desktop, None);
    }

    #[test]
    fn disabled_desktop_home_sentinel_is_not_published() {
        let temp = tempdir().unwrap();
        let environment = test_environment(temp.path());
        fs::write(
            environment
                .xdg_config_home
                .as_ref()
                .unwrap()
                .join("user-dirs.dirs"),
            "XDG_DESKTOP_DIR=\"$HOME/\"\n",
        )
        .unwrap();

        let roots = resolve_linux_shortcut_roots(
            &environment,
            ShortcutPolicy {
                application_menu: false,
                desktop: true,
            },
        )
        .unwrap();
        assert_eq!(roots.application_menu, None);
        assert_eq!(roots.desktop, None);
    }

    #[test]
    fn roots_reject_relative_missing_symlinked_and_non_directory_values() {
        let temp = tempdir().unwrap();
        let mut environment = test_environment(temp.path());
        environment.xdg_data_home = Some(PathBuf::from("relative"));
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: true,
                    desktop: false,
                }
            )
            .is_err()
        );

        let environment = test_environment(temp.path());
        fs::write(
            environment
                .xdg_config_home
                .as_ref()
                .unwrap()
                .join("user-dirs.dirs"),
            "XDG_DESKTOP_DIR=\"relative\"\n",
        )
        .unwrap();
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: false,
                    desktop: true,
                }
            )
            .is_err()
        );

        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let linked = environment.home.join("linked-desktop");
        symlink(&outside, &linked).unwrap();
        fs::write(
            environment
                .xdg_config_home
                .as_ref()
                .unwrap()
                .join("user-dirs.dirs"),
            "XDG_DESKTOP_DIR=\"$HOME/linked-desktop\"\n",
        )
        .unwrap();
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: false,
                    desktop: true,
                }
            )
            .is_err()
        );

        let file = environment.home.join("desktop-file");
        fs::write(&file, b"x").unwrap();
        fs::write(
            environment
                .xdg_config_home
                .as_ref()
                .unwrap()
                .join("user-dirs.dirs"),
            format!("XDG_DESKTOP_DIR=\"{}\"\n", file.display()),
        )
        .unwrap();
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: false,
                    desktop: true,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_oversized_or_malformed_config_without_profile_mutation() {
        let temp = tempdir().unwrap();
        let environment = test_environment(temp.path());
        let config = environment
            .xdg_config_home
            .as_ref()
            .unwrap()
            .join("user-dirs.dirs");
        fs::write(&config, vec![b'a'; MAX_USER_DIRS_BYTES as usize + 1]).unwrap();
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: false,
                    desktop: true,
                }
            )
            .is_err()
        );
        assert_eq!(
            fs::metadata(&config).unwrap().len(),
            MAX_USER_DIRS_BYTES + 1
        );

        fs::write(&config, "XDG_DESKTOP_DIR=$HOME/Desktop\n").unwrap();
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: false,
                    desktop: true,
                }
            )
            .is_err()
        );
        fs::write(
            &config,
            "XDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DESKTOP_DIR=\"$HOME/Other\"\n",
        )
        .unwrap();
        assert!(
            resolve_linux_shortcut_roots(
                &environment,
                ShortcutPolicy {
                    application_menu: false,
                    desktop: true,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn desktop_entry_path_uses_only_authenticated_package_id() {
        let id = PackageId::parse("org.example.product").unwrap();
        assert_eq!(
            desktop_entry_path(Path::new("/home/user/.local/share/applications"), &id),
            Path::new("/home/user/.local/share/applications/org.example.product.desktop")
        );
    }

    fn parse_exec_token_for_test(encoded: &str) -> io::Result<String> {
        let mut desktop = String::new();
        let mut characters = encoded.chars();
        while let Some(character) = characters.next() {
            if character == '\\' {
                let escaped = characters
                    .next()
                    .ok_or_else(|| invalid_data("trailing desktop-entry escape"))?;
                match escaped {
                    '\\' => desktop.push('\\'),
                    's' => desktop.push(' '),
                    'n' => desktop.push('\n'),
                    't' => desktop.push('\t'),
                    'r' => desktop.push('\r'),
                    _ => return Err(invalid_data("unsupported desktop-entry escape")),
                }
            } else {
                desktop.push(character);
            }
        }
        let inner = desktop
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| invalid_data("Exec token is not quoted"))?;
        let mut token = String::new();
        let mut characters = inner.chars();
        while let Some(character) = characters.next() {
            if character == '\\' {
                let escaped = characters
                    .next()
                    .ok_or_else(|| invalid_data("trailing Exec escape"))?;
                if !matches!(escaped, '"' | '`' | '$' | '\\') {
                    return Err(invalid_data("unsupported Exec escape"));
                }
                token.push(escaped);
            } else {
                token.push(character);
            }
        }
        Ok(token)
    }
}

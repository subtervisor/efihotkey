use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::fd::AsRawFd,
};

use bimap::BiMap;
use binread::{until_eof, BinRead, BinReaderExt};
use binwrite::BinWrite;
use bitfield::bitfield;
use clap::{Parser, ValueEnum};
use crc32fast::hash as crc32;

#[derive(ValueEnum, Clone, Debug, PartialEq, PartialOrd)]
enum KeyOperation {
    Get,
    Add,
    Edit,
    Delete,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the Boot variable to boot
    #[arg(long, short)]
    boot_variable: Option<String>,

    /// Key combination to use
    #[arg(long, short)]
    variable: Option<String>,

    /// Key combination to use. Can be specified multiple times for multiple keys.
    #[arg(long, short)]
    key: Vec<String>,

    /// Ignore BootOptionSupport variable settings. Can be useful if your EFI
    /// implementation is buggy and doesn't correctly report this.
    #[arg(long)]
    ignore_support: bool,

    /// Add a key shortcut
    #[arg(short, long, value_enum, default_value_t = KeyOperation::Get)]
    operation: KeyOperation,
}

static EFIVARFS_PATH: &'static str = "/sys/firmware/efi/efivars";
static EFIVAR_SUFFIX: &'static str = "-8be4df61-93ca-11d2-aa0d-00e098032b8c";

static mut EFI_SCAN_CODES: Option<BiMap<&'static str, u16>> = None;
fn init_scan_codes() {
    unsafe {
        EFI_SCAN_CODES = Some(BiMap::from_iter(vec![
            ("Null", 0x00),
            ("UpArrow", 0x01),
            ("DownArrow", 0x02),
            ("RightArrow", 0x03),
            ("LeftArrow", 0x04),
            ("Home", 0x05),
            ("End", 0x06),
            ("Insert", 0x07),
            ("Delete", 0x08),
            ("PageUp", 0x09),
            ("PageDown", 0x0A),
            ("F1", 0x0B),
            ("F2", 0x0C),
            ("F3", 0x0D),
            ("F4", 0x0E),
            ("F5", 0x0F),
            ("F6", 0x10),
            ("F7", 0x11),
            ("F8", 0x12),
            ("F9", 0x13),
            ("F10", 0x14),
            ("F11", 0x15),
            ("F12", 0x16),
            ("Esc", 0x17),
            ("Pause", 0x48),
            ("F13", 0x68),
            ("F14", 0x69),
            ("F15", 0x6A),
            ("F16", 0x6B),
            ("F17", 0x6C),
            ("F18", 0x6D),
            ("F19", 0x6E),
            ("F20", 0x6F),
            ("F21", 0x70),
            ("F22", 0x71),
            ("F23", 0x72),
            ("F24", 0x73),
            ("Mute", 0x7F),
            ("VolUp", 0x80),
            ("VolDown", 0x81),
            ("BrightnessUp", 0x100),
            ("BrightnessDown", 0x101),
            ("Suspend", 0x102),
            ("Hibernate", 0x103),
            ("ToggleDisplay", 0x104),
            ("Recovery", 0x105),
            ("Eject", 0x106),
        ]));
    }
}
fn get_scan_code_name(code: &u16) -> &str {
    let codes = unsafe {
        EFI_SCAN_CODES
            .as_mut()
            .expect("EFI Scan Codes uninitialized!")
    };
    if let Some(name) = codes.get_by_right(code) {
        return *name;
    }
    let key_fmt = Box::leak(format!("{:#06x}", code).into_boxed_str());
    codes.insert(key_fmt, *code);
    key_fmt
}
fn get_scan_code(name: &str) -> Option<&u16> {
    unsafe {
        EFI_SCAN_CODES
            .as_ref()
            .expect("EFI Scan Codes uninitialized!")
            .get_by_left(name)
    }
}

fn is_hexnum(c: char) -> bool {
    c.is_digit(16)
}

bitfield! {
    #[derive(BinRead, PartialEq, Eq, PartialOrd, Ord)]
    struct EfiBootKeyData(u32);
    impl Debug;
    u32;
    get_revision, _: 7, 0;
    get_shift_pressed, set_shift_pressed: 8, 8;
    get_control_pressed, set_control_pressed: 9, 9;
    get_alt_pressed, set_alt_pressed: 10, 10;
    get_logo_pressed, set_logo_pressed: 11, 11;
    get_menu_pressed, set_menu_pressed: 12, 12;
    get_sysrq_pressed, set_sysrq_pressed: 13, 13;
    get_input_key_count, set_input_key_count: 31, 30;
}

bitfield! {
    struct EfiBootSupport(u32);
    u8;
    get_hotkeys_supported, _: 0, 0;
    /* Don't really care about these fields
    get_apps_supported, _: 1, 1;
    get_sysprep_supported, _: 4, 4;
    */
    get_max_key_count, _: 9, 8;
}

impl std::fmt::Display for EfiBootSupport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(Hotkeys: {}, Max Keys per Hotkey: {})",
            if self.get_hotkeys_supported() == 1 {
                "Supported"
            } else {
                "Unsupported"
            },
            self.get_max_key_count(),
        )
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EfiKey {
    scan_code: u16,
    unicode_char: u16,
}

impl std::fmt::Display for EfiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.scan_code == 0 && self.unicode_char == 0 {
            write!(f, "Null")
        } else if self.scan_code != 0 && self.unicode_char == 0 {
            write!(f, "{}", get_scan_code_name(&self.scan_code))
        } else if self.scan_code == 0 && self.unicode_char != 0 {
            match self.unicode_char {
                0x08 => write!(f, "Backspace"),
                0x09 => write!(f, "Tab"),
                0x1B => write!(f, "Escape"),
                0x20 => write!(f, "Space"),
                0x7F => write!(f, "Delete"),
                _ => {
                    let slice = [self.unicode_char];
                    write!(
                        f,
                        "{}",
                        String::from_utf16(&slice).unwrap_or("???".to_string())
                    )
                }
            }
        } else {
            write!(f, "???")
        }
    }
}

fn ebkd_as_u32(e: &EfiBootKeyData) -> u32 {
    unsafe { *(e as *const EfiBootKeyData as *const u32) }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[binwrite(little)]
struct EfiKeyOption {
    #[binwrite(preprocessor(ebkd_as_u32))]
    key_data: EfiBootKeyData,
    boot_option_crc: u32,
    boot_option: u16,
    #[br(count = key_data.get_input_key_count())]
    keys: Vec<EfiKey>,
}

impl std::fmt::Display for EfiKeyOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(BootVar: Boot{:04x}, BootCRC: {:08x}, Hotkey: ",
            self.boot_option, self.boot_option_crc
        )?;
        let mut key_names = Vec::new();
        if self.key_data.get_shift_pressed() == 1 {
            key_names.push("Shift");
        }
        if self.key_data.get_control_pressed() == 1 {
            key_names.push("Control");
        }
        if self.key_data.get_alt_pressed() == 1 {
            key_names.push("Alt");
        }
        if self.key_data.get_logo_pressed() == 1 {
            key_names.push("Logo");
        }
        if self.key_data.get_menu_pressed() == 1 {
            key_names.push("Menu");
        }
        if self.key_data.get_sysrq_pressed() == 1 {
            key_names.push("SysRq");
        }
        let mut combo = key_names.drain(..).peekable();
        while let Some(key) = combo.next() {
            write!(f, "{}", key)?;
            if combo.peek().is_some() || !self.keys.is_empty() {
                write!(f, "-")?;
            }
        }
        let mut keys = self.keys.iter().peekable();
        while let Some(key) = keys.next() {
            write!(f, "{}", key)?;
            if keys.peek().is_some() {
                write!(f, "-")?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl EfiKeyOption {
    fn verify(&self) -> bool {
        let sz_ck = self.key_data.get_input_key_count() as usize == self.keys.len();
        let key_sanity = self.key_data.get_input_key_count() != 0
            || (self.key_data.get_shift_pressed() != 0
                || self.key_data.get_control_pressed() != 0
                || self.key_data.get_alt_pressed() != 0
                || self.key_data.get_logo_pressed() != 0
                || self.key_data.get_menu_pressed() != 0
                || self.key_data.get_sysrq_pressed() != 0);
        sz_ck && key_sanity
    }

    fn verify_boot(&self, boot: &Vec<u8>, boot_num: u16) -> bool {
        let base = self.verify();
        let boot_num_check = boot_num == self.boot_option;
        let crc_pass = self.boot_option_crc == crc32(boot);
        base && boot_num_check && crc_pass
    }
}

#[derive(BinRead, Debug)]
#[br(assert(_file_path_list_length != 0))]
struct EfiLoadOption {
    _attributes: u32,
    _file_path_list_length: u16,
    description: binread::NullWideString,
    #[br(count = _file_path_list_length)]
    _file_path_list: Vec<u8>,
    #[br(parse_with = until_eof)]
    _optional_data: Vec<u8>,
}

fn parse_hotkeys(
    hotkeys: &Vec<String>,
    support_info: &EfiBootSupport,
) -> Option<(EfiBootKeyData, Vec<EfiKey>)> {
    if hotkeys.is_empty() || support_info.get_hotkeys_supported() == 0 {
        return None;
    }

    let mut key_data = EfiBootKeyData(0);
    let mut keys = Vec::new();

    let mut seen_keys = std::collections::HashSet::new();

    for f in hotkeys.iter() {
        let enc = f.encode_utf16().collect::<Vec<_>>();
        if enc.len() == 1 {
            if !seen_keys.contains(f.as_str()) {
                if keys.len() < support_info.get_max_key_count() as usize {
                    seen_keys.insert(f.clone());
                    keys.push(EfiKey {
                        scan_code: 0,
                        unicode_char: enc[0],
                    });
                } else {
                    eprintln!(
                        "More than maximum of {} keys specified!",
                        support_info.get_max_key_count()
                    );
                    return None;
                }
            }
        } else {
            if seen_keys.contains(f.as_str()) {
                continue;
            }
            seen_keys.insert(f.clone());
            match f.as_str() {
                "Shift" => key_data.set_shift_pressed(1),
                "Ctrl" => key_data.set_control_pressed(1),
                "Alt" => key_data.set_alt_pressed(1),
                "Logo" => key_data.set_logo_pressed(1),
                "Menu" => key_data.set_menu_pressed(1),
                "SysRq" => key_data.set_sysrq_pressed(1),
                str_val => {
                    if let Some(scan_code) = get_scan_code(str_val) {
                        if keys.len() < support_info.get_max_key_count() as usize {
                            keys.push(EfiKey {
                                scan_code: *scan_code,
                                unicode_char: 0,
                            });
                        } else {
                            eprintln!(
                                "More than maximum of {} keys specified!",
                                support_info.get_max_key_count()
                            );
                            return None;
                        }
                    } else {
                        eprintln!("Not a valid unicode character or EFI scan code: {}", f);
                        return None;
                    }
                }
            }
        }
    }

    key_data.set_input_key_count(keys.len() as u32);

    Some((key_data, keys))
}

fn get_var(name: &str) -> Option<Vec<u8>> {
    let mut var_name = name.to_string();
    var_name.push_str(EFIVAR_SUFFIX);
    let var_path = std::path::PathBuf::from(EFIVARFS_PATH).join(var_name);
    if let Ok(mut f) = OpenOptions::new()
        .read(true)
        .write(false)
        .append(false)
        .create(false)
        .open(&var_path)
    {
        let mut dummy = [0u8, 0u8, 0u8, 0u8];
        f.read(&mut dummy).ok()?;
        let mut v = Vec::new();
        f.read_to_end(&mut v).ok()?;
        Some(v)
    } else {
        None
    }
}

fn get_vars() -> Option<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(EFIVARFS_PATH).ok()? {
        let entry = entry.ok()?;
        if entry
            .file_name()
            .to_str()
            .unwrap_or_default()
            .ends_with(EFIVAR_SUFFIX)
        {
            out.push(
                entry
                    .file_name()
                    .to_str()
                    .unwrap()
                    .trim_end_matches(EFIVAR_SUFFIX)
                    .to_string(),
            );
        }
    }
    Some(out)
}

fn get_hotkey_support_info(ignore_boot_support: bool) -> EfiBootSupport {
    if ignore_boot_support {
        return EfiBootSupport(0xffff);
    }

    let var_str = String::from("BootOptionSupport");
    if check_var_exists(&var_str) {
        if let Some(data) = get_var(&var_str) {
            let mut reader = std::io::Cursor::new(&data);
            if let Ok(key_option) = reader.read_le::<u32>() {
                return EfiBootSupport(key_option);
            }
        }
    }
    EfiBootSupport(0)
}

fn show_key_info(
    boot_var: Option<String>,
    key_var: Option<String>,
    hotkeys: Option<(EfiBootKeyData, Vec<EfiKey>)>,
    support_info: EfiBootSupport,
    overridden: bool,
) {
    let boot_var = boot_var.map(|s| {
        let hex = s.trim_start_matches("Boot");
        u16::from_str_radix(hex, 16).expect("Failed to parse Boot argument into u16")
    });

    if !overridden {
        println!("Boot Support Info: {}", support_info);
    } else {
        let support_info_real = get_hotkey_support_info(false);
        println!("Boot Support Info (Fake): {}", support_info);
        println!("Boot Support Info (Actual): {}", support_info_real);
    }

    let boot_vars = get_vars().expect("Failed to get variable names");
    let boot_vars = boot_vars
        .iter()
        .filter(|v| {
            return v.len() == 8 && v.starts_with("Boot") && v[4..].chars().all(is_hexnum);
        })
        .filter_map(|n| {
            let buf = get_var(n).expect("Failed to get variable");
            let mut reader = std::io::Cursor::new(&buf);
            let info = reader.read_le::<EfiLoadOption>();
            if info.is_err() {
                eprintln!("Failed to parse {}", n);
                return None;
            }
            let info = info.unwrap();
            Some((n, info.description))
        })
        .collect::<Vec<_>>();

    println!("Boot Options:");
    for p in boot_vars.iter() {
        println!("- {} ({})", p.0, p.1.clone().into_string());
    }
    if boot_vars.is_empty() {
        println!("No boot options found!");
    }
    println!();
    if support_info.get_hotkeys_supported() == 1 {
        let key_vars = get_vars().expect("Failed to get variable names");
        let key_vars = key_vars
            .iter()
            .filter(|v| {
                if key_var.is_some() {
                    return key_var.as_ref().unwrap() == *v;
                }
                return v.len() == 7 && v.starts_with("Key") && v[3..].chars().all(is_hexnum);
            })
            .filter_map(|n| {
                let buf = get_var(n).expect("Failed to get variable");
                let mut reader = std::io::Cursor::new(&buf);
                let key_option = reader.read_le::<EfiKeyOption>();
                if key_option.is_err() {
                    eprintln!("Failed to parse {}", n);
                    return None;
                }
                let key_option = key_option.unwrap();
                if let Some(boot_var) = boot_var {
                    if key_option.boot_option != boot_var {
                        return None;
                    }
                }

                if let Some((key_info, keys)) = hotkeys.as_ref() {
                    if &key_option.key_data != key_info || &key_option.keys != keys {
                        return None;
                    }
                }
                Some((n, key_option))
            })
            .collect::<Vec<_>>();

        println!("Hotkeys:");

        for p in key_vars.iter() {
            println!("- {}: {}", p.0, p.1);
        }
        if key_vars.is_empty() {
            if boot_var.is_none() && key_var.is_none() && hotkeys.is_none() {
                println!("No hotkeys found!");
            } else {
                println!("No hotkeys found matching arguments!");
            }
        }
    } else {
        println!("Hotkeys unsupported!");
    }
}

fn efi_var_path(var: &str) -> std::path::PathBuf {
    let mut var_filename = var.to_string();
    var_filename.push_str(EFIVAR_SUFFIX);
    std::path::PathBuf::from(EFIVARFS_PATH).join(var_filename)
}

fn check_var_exists(var: &str) -> bool {
    efi_var_path(var).exists()
}

use libc::c_ulong;
use nix::{ioctl_read, ioctl_write_ptr};

const FS_IOC_GETFLAGS_MAGIC: u8 = b'f';
const FS_IOC_GETFLAGS_MODE: u8 = 1;
const FS_IOC_SETFLAGS_MODE: u8 = 2;
ioctl_read!(
    fs_get_flags,
    FS_IOC_GETFLAGS_MAGIC,
    FS_IOC_GETFLAGS_MODE,
    c_ulong
);

ioctl_write_ptr!(
    fs_set_flags,
    FS_IOC_GETFLAGS_MAGIC,
    FS_IOC_SETFLAGS_MODE,
    c_ulong
);

fn try_delete_var(name: &str, write: bool) -> bool {
    let var_path = efi_var_path(&name);
    if let Ok(f) = OpenOptions::new()
        .read(!write)
        .write(write)
        .append(false)
        .create(false)
        .open(&var_path)
    {
        unsafe {
            let mut attribs = 0;
            if let Ok(_) = fs_get_flags(f.as_raw_fd(), &mut attribs) {
                if attribs & 0x00000010 != 0 {
                    let new_attribs = attribs & !0x00000010;
                    if let Err(e) = fs_set_flags(f.as_raw_fd(), &new_attribs) {
                        eprintln!("Failed to make variable mutable: {}", e);
                    }
                }
            }
        }
    }
    std::fs::remove_file(var_path).is_ok()
}

fn delete_hotkey(key_var: String, support_info: &EfiBootSupport) {
    if support_info.get_hotkeys_supported() == 0 {
        eprintln!("Hotkeys are not supported!");
        return;
    }

    let key_var = if key_var.starts_with("Key") {
        key_var
    } else {
        format!("Key{}", key_var)
    };

    if check_var_exists(&key_var) {
        if !try_delete_var(&key_var, false) && !try_delete_var(&key_var, true) {
            eprintln!("Failed to delete!");
        }
    }
}

fn edit_hotkey(
    boot_var: Option<String>,
    key_var: String,
    hotkeys: Option<(EfiBootKeyData, Vec<EfiKey>)>,
    support_info: &EfiBootSupport,
) {
    let key_var = if key_var.starts_with("Key") {
        key_var
    } else {
        format!("Key{}", key_var)
    };

    if support_info.get_hotkeys_supported() != 1 {
        eprintln!("Hotkeys are not supported!");
        return;
    }

    if !check_var_exists(&key_var) {
        eprintln!("{} does not exist!", key_var);
        std::process::exit(-2);
    }

    let boot_var = boot_var.map(|boot_var| {
        let boot_var_hex = boot_var.trim_start_matches("Boot");
        let boot_var_u16 =
            u16::from_str_radix(boot_var_hex, 16).expect("Failed to parse Boot argument into u16");

        let boot_var = if boot_var.starts_with("Boot") {
            boot_var
        } else {
            format!("Boot{}", boot_var)
        };

        let buf = get_var(&boot_var);
        if buf.is_none() {
            eprintln!("Failed to get {}!", boot_var);
            std::process::exit(-2);
        }
        let buf = buf.unwrap();
        let boot_var_crc = crc32(&buf);
        (boot_var_u16, boot_var_crc, buf)
    });

    let buf = get_var(&key_var).expect("Failed to get key variable");
    let mut reader = std::io::Cursor::new(&buf);
    let key_option = reader.read_le::<EfiKeyOption>();
    if key_option.is_err() {
        eprintln!("Failed to parse {}", key_var);
        std::process::exit(-3);
    }
    let mut key_option = key_option.unwrap();
    if let Some(hotkey_info) = hotkeys {
        key_option.key_data = hotkey_info.0;
        key_option.keys = hotkey_info.1;
        if !key_option.verify() {
            eprintln!("Failed to verify key struct after updating hotkeys.");
            std::process::exit(-3);
        }
    }
    if let Some(boot_data) = boot_var {
        key_option.boot_option = boot_data.0;
        key_option.boot_option_crc = boot_data.1;
        if !key_option.verify_boot(&boot_data.2, boot_data.0) {
            eprintln!("Failed to verify key struct after updating hotkeys.");
            std::process::exit(-3);
        }
    }
    println!("Saving hotkey: {}", key_option);
    let mut key_bytes = vec![];
    if let Err(e) = key_option.write(&mut key_bytes) {
        eprintln!("Failed to encode hotkey struct: {}", e);
        std::process::exit(-3);
    }

    let var_path = efi_var_path(&key_var);
    let mut original_attribs = None;
    let mut attrib_fd = None;
    if let Ok(f) = OpenOptions::new()
        .read(true)
        .write(false)
        .append(false)
        .create(false)
        .open(&var_path)
    {
        unsafe {
            let mut attribs = 0;
            if let Ok(_) = fs_get_flags(f.as_raw_fd(), &mut attribs) {
                if attribs & 0x00000010 != 0 {
                    let new_attribs = attribs & !0x00000010;
                    if let Err(e) = fs_set_flags(f.as_raw_fd(), &new_attribs) {
                        eprintln!("Failed to make variable mutable: {}", e);
                    } else {
                        original_attribs = Some(attribs);
                        attrib_fd = Some(f);
                    }
                }
            }
        }
    }

    if let Ok(mut f) = OpenOptions::new()
        .read(false)
        .write(true)
        .append(false)
        .create(false)
        .open(&var_path)
    {
        unsafe {
            let mut attribs = 0;
            if let Ok(_) = fs_get_flags(f.as_raw_fd(), &mut attribs) {
                if attribs & 0x00000010 != 0 {
                    let new_attribs = attribs & !0x00000010;
                    if let Err(e) = fs_set_flags(f.as_raw_fd(), &new_attribs) {
                        eprintln!("Failed to make variable mutable: {}", e);
                        return;
                    } else {
                        original_attribs = Some(attribs);
                        attrib_fd = None;
                    }
                }
            }
        }

        let mut buf = (0x00000007 as u32).to_le_bytes().to_vec();
        buf.append(&mut key_bytes);
        if let Err(e) = f.write_all(&mut buf) {
            eprintln!("Failed to write var: {}", e);
        }

        if original_attribs.is_some() {
            let mut original_attribs = original_attribs.unwrap();
            let f = attrib_fd.unwrap_or(f);
            unsafe {
                if let Err(e) = fs_set_flags(f.as_raw_fd(), &mut original_attribs) {
                    eprintln!("Failed to make variable immutable: {}", e);
                }
            }
        }
    }
}

fn add_hotkey(
    boot_var: String,
    key_var: Option<String>,
    hotkeys: (EfiBootKeyData, Vec<EfiKey>),
    support_info: &EfiBootSupport,
) {
    let key_var = key_var.map(|v| {
        if v.starts_with("Key") {
            v
        } else {
            format!("Key{}", v)
        }
    });

    if support_info.get_hotkeys_supported() != 1 {
        eprintln!("Hotkeys are not supported!");
        return;
    }

    if let Some(key_var) = key_var.as_ref() {
        if check_var_exists(key_var) {
            eprintln!("Key variable {} already exists!", key_var);
            std::process::exit(-2);
        }
    }

    let boot_var_hex = boot_var.trim_start_matches("Boot");
    let boot_var_u16 =
        u16::from_str_radix(boot_var_hex, 16).expect("Failed to parse Boot argument into u16");

    let boot_var = if boot_var.starts_with("Boot") {
        boot_var
    } else {
        format!("Boot{}", boot_var)
    };

    let buf = get_var(&boot_var);
    if buf.is_none() {
        eprintln!("Failed to get {}!", boot_var);
        std::process::exit(-2);
    }
    let buf = buf.unwrap();
    let boot_var_crc = crc32(&buf);
    let hotkey_info = EfiKeyOption {
        key_data: hotkeys.0,
        boot_option_crc: boot_var_crc,
        boot_option: boot_var_u16,
        keys: hotkeys.1,
    };

    if !hotkey_info.verify_boot(&buf, boot_var_u16) {
        eprintln!("Failed to verify hotkey struct.");
        std::process::exit(-3);
    }

    let key_var_name_str = key_var.unwrap_or_else(|| {
        let mut idx: u16 = 0;
        loop {
            let candidate = format!("Key{:04x}", idx);
            if !check_var_exists(&candidate) {
                return candidate;
            }
            idx += 1;
        }
    });
    println!("Saving hotkey: {}", hotkey_info);
    let mut key_bytes = vec![];
    if let Err(e) = hotkey_info.write(&mut key_bytes) {
        eprintln!("Failed to encode hotkey struct: {}", e);
        std::process::exit(-3);
    }

    let var_path = efi_var_path(&key_var_name_str);

    if let Ok(mut f) = OpenOptions::new()
        .read(false)
        .write(true)
        .append(false)
        .create(true)
        .open(var_path)
    {
        let mut buf = (0x00000007 as u32).to_le_bytes().to_vec();
        buf.append(&mut key_bytes);
        if let Err(e) = f.write_all(&mut buf) {
            eprintln!("Failed to write var: {}", e);
        }
    }
}

fn main() {
    init_scan_codes();
    let args = Args::parse();

    if let Some(boot_arg) = args.boot_variable.as_ref() {
        if !(boot_arg.len() == 4 && boot_arg.chars().all(is_hexnum))
            && !(boot_arg.len() == 8
                && boot_arg.starts_with("Boot")
                && boot_arg[4..].chars().all(is_hexnum))
        {
            eprintln!("Boot entry name must be in 0000 or Boot0000 format");
            std::process::exit(-1);
        }
    }

    if let Some(keyvar_arg) = args.variable.as_ref() {
        if !(keyvar_arg.len() == 4 && keyvar_arg.chars().all(is_hexnum))
            && !(keyvar_arg.len() == 7
                && keyvar_arg.starts_with("Key")
                && keyvar_arg[3..].chars().all(is_hexnum))
        {
            eprintln!("Key entry name must be in 0000 or Key0000 format");
            std::process::exit(-1);
        }
    }

    let support_info = get_hotkey_support_info(args.ignore_support);

    let hotkeys = parse_hotkeys(&args.key, &support_info);
    if hotkeys.is_none() && !args.key.is_empty() {
        eprintln!("Failed to parse keys!");
        std::process::exit(-1);
    }

    match args.operation {
        KeyOperation::Get => {
            show_key_info(
                args.boot_variable,
                args.variable,
                hotkeys,
                support_info,
                args.ignore_support,
            );
        }
        KeyOperation::Add => {
            if args.boot_variable.is_none() || args.key.is_empty() {
                eprintln!(
                    "Adding a hotkey requires providing a boot variable and at least one key!"
                );
                std::process::exit(-1);
            }
            add_hotkey(
                args.boot_variable.unwrap(),
                args.variable,
                hotkeys.unwrap(),
                &support_info,
            );
            show_key_info(None, None, None, support_info, args.ignore_support);
        }
        KeyOperation::Edit => {
            if args.boot_variable.is_none() && hotkeys.is_none() {
                eprintln!("Editing requires providing a hotkey or boot option to save.");
                std::process::exit(-2);
            }
            if args.variable.is_none() {
                eprintln!("Editing requires a Key variable to edit.");
                std::process::exit(-1);
            }
            edit_hotkey(
                args.boot_variable,
                args.variable.unwrap(),
                hotkeys,
                &support_info,
            );
            show_key_info(None, None, None, support_info, args.ignore_support);
        }
        KeyOperation::Delete => {
            if args.boot_variable.is_some() || hotkeys.is_some() {
                eprintln!("When deleting a hotkey, only key variable may be provided.");
                std::process::exit(-1);
            }
            if args.variable.is_none() {
                eprintln!("Key variable required for deletion.");
                std::process::exit(-1);
            }
            delete_hotkey(args.variable.unwrap(), &support_info);
            show_key_info(None, None, None, support_info, args.ignore_support);
        }
    }
}

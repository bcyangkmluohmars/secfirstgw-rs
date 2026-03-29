// GPIO chardev ioctls require unsafe — this is the only module that uses it.
#![allow(clippy::needless_range_loop)]
#![allow(unsafe_code)]

//! Background LED service — drives bay LEDs via `/dev/gpiochipN` chardev ioctl.
//!
//! | Mode         | White (SGPO) | Red (PCA9575) |
//! |--------------|--------------|---------------|
//! | Off          | off          | off           |
//! | Normal       | steady       | off           |
//! | Active       | blink 1Hz    | off           |
//! | SmartWarning | off          | blink 1Hz     |
//! | Degraded     | off          | steady        |
//! | Identify     | alt blink    | alt blink     |

use crate::bay::{LED_RED_CHIP, LED_RED_PIN, LED_WHITE_CHIP, LED_WHITE_PIN};
use crate::{Bay, BayLedMode, BayState, DiskCache, SmartStatus};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

// ---- GPIO chardev v2 ioctl structs (from <linux/gpio.h>) ----

// From linux/gpio.h — _IOWR(0xB4, 0x07, gpio_v2_line_request) and _IOWR(0xB4, 0x0F, gpio_v2_line_values)
// Cast via nix::request_code_readwrite! or hardcode for portability.
const GPIO_V2_GET_LINE_IOCTL: libc::c_ulong = 0xC250B407;
const GPIO_V2_LINE_SET_VALUES_IOCTL: libc::c_ulong = 0xC010B40F; // 0x0F not 0x0D!
const GPIO_V2_LINE_FLAG_OUTPUT: u64 = 0x08;

// Exact kernel struct layout — total sizeof(gpio_v2_line_request) = 592
#[repr(C)]
struct GpioV2LineRequest {
    offsets: [u32; 64],       // 256
    consumer: [u8; 32],       // 32
    config: GpioV2LineConfig, // 272
    num_lines: u32,           // 4
    event_buffer_size: u32,   // 4
    _padding: [u32; 5],       // 20
    fd: i32,                  // 4
} // = 592

#[repr(C)]
struct GpioV2LineConfig {
    flags: u64,                        // 8
    num_attrs: u32,                    // 4
    _padding: [u32; 5],                // 20
    attrs: [GpioV2LineConfigAttr; 10], // 240
} // = 272

#[repr(C)]
#[derive(Copy, Clone)]
struct GpioV2LineConfigAttr {
    attr: [u8; 16], // gpio_v2_line_attribute
    mask: u64,      // 8
} // = 24

#[repr(C)]
struct GpioV2LineValues {
    bits: u64,
    mask: u64,
}

/// A handle to claimed GPIO lines on one chip.
struct GpioLines {
    fd: i32,
    // We keep the file open so the fd stays valid
    _chip: File,
    _request_fd_owner: File,
    pin_count: usize,
}

impl GpioLines {
    fn open(chip_num: u8, pins: &[u8]) -> io::Result<Self> {
        let path = format!("/dev/gpiochip{chip_num}");
        let chip = OpenOptions::new().read(true).write(true).open(&path)?;

        let mut req = GpioV2LineRequest {
            offsets: [0u32; 64],
            consumer: [0u8; 32],
            config: GpioV2LineConfig {
                flags: GPIO_V2_LINE_FLAG_OUTPUT,
                num_attrs: 0,
                _padding: [0; 5],
                attrs: [GpioV2LineConfigAttr {
                    attr: [0; 16],
                    mask: 0,
                }; 10],
            },
            num_lines: pins.len() as u32,
            event_buffer_size: 0,
            _padding: [0; 5],
            fd: 0,
        };

        // Set pin offsets
        for (i, &pin) in pins.iter().enumerate() {
            req.offsets[i] = pin as u32;
        }

        // Set consumer name
        let name = b"secfirstnas-led";
        req.consumer[..name.len()].copy_from_slice(name);

        // SAFETY: Valid fd from /dev/gpiochipN, req is correctly sized GpioV2LineRequest.
        // Kernel writes the granted line fd into req.fd.
        let ret = unsafe { libc::ioctl(chip.as_raw_fd(), GPIO_V2_GET_LINE_IOCTL as _, &mut req) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: req.fd is a valid fd returned by the GPIO_V2_GET_LINE_IOCTL above.
        // We take ownership so it gets closed on drop.
        let request_fd_owner = unsafe {
            use std::os::unix::io::FromRawFd;
            File::from_raw_fd(req.fd)
        };

        Ok(Self {
            fd: req.fd,
            _chip: chip,
            _request_fd_owner: request_fd_owner,
            pin_count: pins.len(),
        })
    }

    fn set(&self, values: &[bool]) {
        let mut bits: u64 = 0;
        let mut mask: u64 = 0;
        for i in 0..self.pin_count.min(values.len()) {
            mask |= 1 << i;
            if values[i] {
                bits |= 1 << i;
            }
        }

        let vals = GpioV2LineValues { bits, mask };
        // SAFETY: self.fd is the valid line request fd, vals is correctly sized.
        let _ = unsafe { libc::ioctl(self.fd, GPIO_V2_LINE_SET_VALUES_IOCTL as _, &vals) };
    }
}

// ---- LED Service ----

pub struct LedService {
    stop: Arc<AtomicBool>,
}

impl LedService {
    pub fn start(cache: DiskCache) -> Option<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();

        match thread::Builder::new()
            .name("led-service".into())
            .spawn(move || run(cache, stop_clone))
        {
            Ok(_) => {
                info!("LED service started");
                Some(Self { stop })
            }
            Err(e) => {
                warn!(error = %e, "failed to spawn LED service thread — LEDs disabled");
                None
            }
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for LedService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(cache: DiskCache, stop: Arc<AtomicBool>) {
    // Open GPIO chips and claim lines — held for lifetime of service
    let white = match GpioLines::open(LED_WHITE_CHIP, &LED_WHITE_PIN) {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "LED service: failed to open SGPO gpiochip — LEDs disabled");
            return;
        }
    };
    let red = match GpioLines::open(LED_RED_CHIP, &LED_RED_PIN) {
        Ok(g) => g,
        Err(e) => {
            warn!(error = %e, "LED service: failed to open PCA9575 gpiochip — fault LEDs disabled");
            return;
        }
    };

    // Boot animation
    boot_animation(&white, &red);

    let mut tick: u32 = 0;

    while !stop.load(Ordering::Relaxed) {
        let bays = Bay::read_all();
        let disks = cache.get();
        let arrays = cache.get_arrays();

        let raid_degraded = arrays.iter().any(|a| {
            let s = a.state.to_lowercase();
            s.contains("degraded") || s.contains("rebuild") || s.contains("recover")
        });

        let blink_on = tick.is_multiple_of(2);
        let mut w = [false; 4];
        let mut r = [false; 4];

        for bay in &bays {
            let idx = (bay.slot - 1) as usize;
            if idx >= 4 {
                continue;
            }

            let mode = if bay.state != BayState::Present {
                BayLedMode::Off
            } else {
                let disk = bay
                    .map_to_disk()
                    .ok()
                    .and_then(|path| disks.iter().find(|d| d.path == path));

                match disk {
                    Some(d)
                        if d.is_failing()
                            || matches!(d.health.smart_status, SmartStatus::Failed(_)) =>
                    {
                        BayLedMode::SmartWarning
                    }
                    _ if raid_degraded => BayLedMode::Degraded,
                    Some(_) if has_io_activity(bay) => BayLedMode::Active,
                    _ => BayLedMode::Normal,
                }
            };

            let (wv, rv) = match mode {
                BayLedMode::Off => (false, false),
                BayLedMode::Normal => (true, false),
                BayLedMode::Active => (blink_on, false),
                BayLedMode::SmartWarning => (false, blink_on),
                BayLedMode::Degraded => (false, true),
                BayLedMode::Identify => (blink_on, !blink_on),
            };

            w[idx] = wv;
            r[idx] = rv;
        }

        white.set(&w);
        red.set(&r);

        tick = tick.wrapping_add(1);
        thread::sleep(Duration::from_millis(250));
    }

    // Shutdown
    white.set(&[false; 4]);
    red.set(&[false; 4]);
}

fn boot_animation(white: &GpioLines, red: &GpioLines) {
    let off = [false; 4];
    let on = [true; 4];

    white.set(&off);
    red.set(&off);
    thread::sleep(Duration::from_millis(300));

    white.set(&on);
    thread::sleep(Duration::from_millis(300));

    red.set(&on);
    thread::sleep(Duration::from_millis(300));

    white.set(&off);
    red.set(&off);
    thread::sleep(Duration::from_millis(200));
}

fn has_io_activity(bay: &Bay) -> bool {
    let dev_path = match bay.map_to_disk() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let dev_name = match dev_path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return false,
    };
    std::fs::read_to_string(format!("/sys/block/{dev_name}/stat"))
        .ok()
        .and_then(|s| s.split_whitespace().nth(8)?.parse::<u64>().ok())
        .map(|inflight| inflight > 0)
        .unwrap_or(false)
}

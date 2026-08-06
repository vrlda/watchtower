//! Linux-only inotify watcher. The platform-free types live in fim_types.
#![cfg(target_os = "linux")]

use std::sync::mpsc::Sender;

use inotify::{Inotify, WatchMask};

use super::fim_types::{mask_name, FimEvent, WatchedFile};

/// Spawn the inotify watcher thread for the given files. Pushes FimEvents
/// into `tx` forever. Parent dirs are watched so atomic renames are caught.
pub fn spawn_watcher(files: Vec<WatchedFile>, tx: Sender<FimEvent>) -> std::io::Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let mut inotify = Inotify::init()?;
    let mut watches = Vec::new();
    for f in &files {
        let wd = inotify.add_watch(
            f.parent(),
            WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::DELETE,
        )?;
        watches.push((wd, f.clone()));
    }
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            let events = match inotify.read_events_blocking(&mut buffer) {
                Ok(events) => events,
                Err(_) => continue,
            };
            for event in events {
                for (wd, file) in &watches {
                    if event.wd == *wd && file.relevant(event.name) {
                        let action = mask_name(event.mask.bits());
                        if tx
                            .send(FimEvent {
                                path: file.path.to_string_lossy().into_owned(),
                                action,
                            })
                            .is_err()
                        {
                            return; // engine gone
                        }
                    }
                }
            }
        }
    });
    Ok(())
}

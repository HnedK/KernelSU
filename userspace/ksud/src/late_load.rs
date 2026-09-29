use anyhow::{Context, Result};
use log::{info, warn};
use prop_rs_android::sys_prop;
use rustix::cstr;
use std::time::Instant;

use crate::module::{ScriptWait, handle_updated_modules, prune_modules};
use crate::{assets, defs, init_event, metamodule, restorecon, utils};

fn dump_process_info(label: &str) {
    use rustix::process::{getgid, getgroups, getpid, getuid};

    let pid = getpid().as_raw_nonzero();
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    let groups: Vec<String> = getgroups()
        .unwrap_or_default()
        .iter()
        .map(|g| g.as_raw().to_string())
        .collect();
    let selinux = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_else(|_| "unknown".to_string());
    let seccomp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Seccomp:"))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        "[{label}] pid={pid}, uid={uid}, gid={gid}, groups=[{}], selinux={}, {seccomp}",
        groups.join(","),
        selinux.trim(),
    );
}

fn clone_pid_environ(pid: u32) {
    if let Ok(env_raw) = std::fs::read(format!("/proc/{pid}/environ")) {
        env_raw
            .split(|&b| b == 0)
            .filter_map(|e| std::str::from_utf8(e).ok())
            .filter_map(|s| s.split_once('='))
            .for_each(|(k, v)| unsafe { std::env::set_var(k, v) });
    }
}

pub fn run(
    _package_name: &String,
    kmi: Option<String>,
    stage_from: &str,
    allow_shell: bool,
) -> Result<()> {
    info!("late-load command triggered!");
    dump_process_info("late-load start");

    // Start with a basic init environ: a late-load inherits whatever the
    // caller had (the blob chain passes a bare modprobe context), and every
    // child we spawn below inherits it from us.
    clone_pid_environ(1);

    // Two install routes, picked by whether the caller pre-staged a daemon:
    //
    // - Stage file present (boot-time flows and su_daemon-style chains write
    //   /data/local/tmp/.ksud-stage themselves): copy it to /data/adb/ksud
    //   *before* the module load, while this process still runs under the
    //   vendor domain. The remaining install steps require KernelSU policy
    //   and run after the load (see finish_install below).
    // - Stage file absent (callers that just exec `ksud late-load`, e.g. the
    //   DirtyFrag blob): keep upstream's flow -- load first, then the running
    //   binary installs itself to /data/adb/ksud under KernelSU's policy.
    let staged = std::path::Path::new(stage_from).exists();
    if staged {
        utils::stage_daemon_from(stage_from).context("Failed to stage ksud")?;
    } else {
        info!("no staged daemon at {stage_from}; installing self after module load");
    }

    // 1. Check if KernelSU is already loaded
    if ksuinit::has_kernelsu() {
        info!("KernelSU already loaded, skip loading ko");
    } else {
        // 2. Detect current KMI version
        let kmi = kmi.map_or_else(
            || crate::boot_patch::get_current_kmi().context("Failed to detect current KMI version"),
            Ok,
        )?;
        info!("Detected KMI: {kmi}");

        // 3. Get kernelsu.ko from embedded assets
        // KSUD_TREE=exynos (injected via UMH envp) selects the -exynos
        // asset with pre-injected __versions; others keep the default one.
        let ko_name = if std::env::var("KSUD_TREE").as_deref() == Ok("exynos") {
            let exynos_name = format!("{kmi}-exynos_kernelsu.ko");
            if assets::get_asset_data(&exynos_name).is_ok() {
                exynos_name
            } else {
                warn!(
                    "KSUD_TREE=exynos set but {exynos_name} asset missing; \
                     falling back to default asset"
                );
                format!("{kmi}_kernelsu.ko")
            }
        } else {
            format!("{kmi}_kernelsu.ko")
        };
        let ko_data = assets::get_asset_data(&ko_name)
            .with_context(|| format!("Failed to get {ko_name} from assets"))?;

        // 4. Load kernelsu.ko from memory with manual relocation
        info!("Loading kernelsu.ko for KMI {kmi}...");
        // bundled flag is meaningless in jailbreak mode since we can't flash boot to update it.
        let params = if allow_shell {
            cstr!("allow_shell=1")
        } else {
            cstr!("")
        };
        ksuinit::load_module(&ko_data, params).context("Failed to load kernelsu.ko")?;
        info!("kernelsu.ko loaded successfully!");
        dump_process_info("after load_module");
    }

    // Say what the module actually reports, now that it is in. Everything
    // below can fail without KernelSU being at fault, and the caller's
    // descriptors stop working the moment the sepolicy is reloaded, so this
    // is the one line that says "it is loaded and answering" somewhere that
    // survives.
    {
        let info = crate::ksucalls::get_info();
        info!(
            "KernelSU live: version={} uapi={} flags=0x{:x} features=0x{:x} late_load={}",
            crate::ksucalls::get_version(),
            info.uapi_version,
            info.flags,
            info.features,
            crate::ksucalls::is_late_load()
        );
    }

    // Rejoin init's mount namespace before touching modules.
    //
    // A late-load is exec'd from a throwaway private namespace: the caller has
    // to unshare(CLONE_NEWNS) to bind-mount this binary over a path it is
    // allowed to exec, and marks / as MS_REC|MS_PRIVATE so that cover does not
    // escape. Everything below -- the metamodule mount, and every module
    // script, which inherits this namespace -- would then run against mounts
    // that die with this process, while the daemons those scripts start keep
    // running and expect them. At boot ksud is already in init's namespace and
    // none of this arises; rejoining reproduces that.
    if let Err(e) = utils::switch_mnt_ns(1) {
        warn!("failed to rejoin init mount namespace: {e}");
    }

    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:vendor_modprobe:s0 instead of u:r:ksu:s0.
    utils::reset_std()?;

    // Upgrade to a full android environ so that modules can be properly loaded
    if sys_prop::init().is_err() {
        warn!("could not init sys_prop, skipping zygote env clone");
    } else if let Some(pid) =
        sys_prop::get("init.svc_debug_pid.zygote").and_then(|val| val.parse::<u32>().ok())
    {
        clone_pid_environ(pid);
        info!("cloned env from zygote pid={pid}");
    }

    // Append KSU binary dir to PATH
    let mut paths: Vec<_> =
        std::env::var_os("PATH").map_or_else(Vec::new, |v| std::env::split_paths(&v).collect());
    paths.push(defs::BINARY_DIR.trim_end_matches('/').into());
    if let Ok(new_path) = std::env::join_paths(paths) {
        unsafe { std::env::set_var("PATH", new_path) };
    }

    utils::umask(0);

    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    // Install route, part two (see the top of run()):
    // - staged: the daemon file is already in place; finish_install() only
    //   runs the remaining steps and must NOT rewrite /data/adb/ksud. After
    //   the module changed this process's security context, writing the
    //   daemon path fails under Samsung KDP/SELinux and leaves a zero-byte
    //   file -- which is exactly why this split exists.
    // - unstaged: upstream's late-load install() -- copy /proc/self/exe to
    //   /data/adb/ksud now that the process runs under KernelSU's policy.
    if staged {
        utils::finish_install(None).context("Failed to finish ksud installation")?;
    } else {
        utils::install(None, None).context("Failed to install ksud")?;
    }

    // 5. Handle module updates
    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // 6. Load SELinux rules
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    // 7. Initialize features
    if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // 8. Execute late-load stage scripts (blocking)
    //
    // Module stage scripts assume the environment a boot gives them: their
    // module mounts already established, and no framework running yet. A
    // late-load can offer neither. What they do instead is start daemons --
    // a Zygisk implementation, LSPosed's lspd, Sui -- against a zygote that
    // is already serving, and those daemons restart it to inject. On warhol
    // that reliably kills system_server: it comes back up and dies in
    // ApplicationSharedMemory.nativeCreate with ENOENT, every time, until
    // the device is rebooted.
    //
    // So they are off unless asked for. KernelSU itself -- su, the manager,
    // the allowlist -- needs none of this; only modules do, and a module
    // that a late-load cannot mount is not one this should be starting.
    let run_module_scripts = std::env::var("KSU_LATE_LOAD_MODULES")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if !run_module_scripts {
        warn!("late-load: skipping module stage scripts (set KSU_LATE_LOAD_MODULES=1 to run them)");
    }

    // Both blocking stages share one boot deadline.
    let wait = ScriptWait::Until(Instant::now() + defs::BOOT_STAGE_TIMEOUT);
    if run_module_scripts {
        init_event::run_stage("late-load", wait);
    }

    // 9. Load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // 10. Execute metamodule mount script (OverlayFS)
    if let Err(e) = metamodule::exec_mount_script(defs::MODULE_DIR) {
        warn!("execute metamodule mount failed: {e}");
    }

    // 11. Execute post-mount stage scripts using the same deadline
    if run_module_scripts {
        init_event::run_stage("post-mount", wait);
    }

    // 12. Execute service stage scripts (non-blocking)
    if run_module_scripts {
        init_event::run_stage("service", ScriptWait::NoWait);
    }

    // 13. Execute boot-completed stage scripts (non-blocking)
    if run_module_scripts {
        init_event::run_stage("boot-completed", ScriptWait::NoWait);
    }

    Ok(())
}

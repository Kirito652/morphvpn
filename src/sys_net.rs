use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::info;
#[cfg(target_os = "linux")]
use tracing::warn;

#[cfg(target_os = "linux")]
const NAT_CHAIN: &str = "MORPHVPN_NAT";
#[cfg(target_os = "linux")]
const FILTER_CHAIN: &str = "MORPHVPN_FWD";

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub tun_name: String,
    pub tun_ip: String,
    pub prefix_len: u8,
    pub gateway_ip: String,
    pub server_ip: Option<IpAddr>,
}

impl NetConfig {
    pub fn server(tun_name: impl Into<String>) -> Self {
        Self {
            tun_name: tun_name.into(),
            tun_ip: "10.8.0.1".into(),
            prefix_len: 24,
            gateway_ip: "10.8.0.2".into(),
            server_ip: None,
        }
    }

    pub fn client(tun_name: impl Into<String>) -> Self {
        Self {
            tun_name: tun_name.into(),
            tun_ip: "10.8.0.2".into(),
            prefix_len: 24,
            gateway_ip: "10.8.0.1".into(),
            server_ip: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DefaultRoute {
    gateway: IpAddr,
    iface: String,
}

pub struct NetworkGuard {
    config: NetConfig,
    #[cfg(target_os = "linux")]
    wan_iface: Option<String>,
    pinned_server_ip: Option<IpAddr>,
    is_server: bool,
    cleaned_up: bool,
}

impl NetworkGuard {
    pub fn cleanup(&mut self) {
        if self.cleaned_up {
            return;
        }
        self.cleaned_up = true;

        #[cfg(target_os = "linux")]
        if self.is_server {
            linux_cleanup_nat(&self.config.tun_name, self.wan_iface.as_deref());
            linux_remove_tun_ip(
                &self.config.tun_name,
                &self.config.tun_ip,
                self.config.prefix_len,
            );
        } else {
            linux_remove_split_default_routes(&self.config.gateway_ip, &self.config.tun_name);
            if let Some(server_ip) = self.pinned_server_ip {
                linux_remove_host_route(server_ip);
            }
        }

        #[cfg(target_os = "windows")]
        if self.is_server {
            let _ = windows_remove_tun_ip(&self.config.tun_name, &self.config.tun_ip);
        } else {
            windows_remove_split_default_routes(&self.config.gateway_ip);
            if let Some(server_ip) = self.pinned_server_ip {
                windows_remove_host_route(server_ip);
            }
        }

        info!("network cleanup completed");
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

pub fn setup_server(config: NetConfig) -> Result<NetworkGuard> {
    #[cfg(target_os = "linux")]
    {
        let wan = linux_detect_wan_iface()?;
        reapply_server_tun(&config)?;
        linux_cleanup_nat(&config.tun_name, Some(&wan));
        linux_add_nat(&config.tun_name, &wan)?;

        return Ok(NetworkGuard {
            config,
            #[cfg(target_os = "linux")]
            wan_iface: Some(wan),
            pinned_server_ip: None,
            is_server: true,
            cleaned_up: false,
        });
    }

    #[cfg(target_os = "windows")]
    {
        let adapter = windows_resolve_adapter_name(&config.tun_name)?;
        windows_assign_ip(&adapter, &config.tun_ip, config.prefix_len)?;
        return Ok(NetworkGuard {
            config,
            pinned_server_ip: None,
            is_server: true,
            cleaned_up: false,
        });
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(NetworkGuard {
            config,
            pinned_server_ip: None,
            is_server: true,
            cleaned_up: false,
        })
    }
}

pub fn setup_client(config: NetConfig) -> Result<NetworkGuard> {
    #[cfg(target_os = "linux")]
    {
        reapply_client_tun(&config)?;

        return Ok(NetworkGuard {
            pinned_server_ip: config.server_ip,
            config,
            is_server: false,
            cleaned_up: false,
        });
    }

    #[cfg(target_os = "windows")]
    {
        reapply_client_tun(&config)?;

        return Ok(NetworkGuard {
            pinned_server_ip: config.server_ip,
            config,
            is_server: false,
            cleaned_up: false,
        });
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(NetworkGuard {
            pinned_server_ip: config.server_ip,
            config,
            is_server: false,
            cleaned_up: false,
        })
    }
}

pub fn reapply_server_tun(config: &NetConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_assign_ip(&config.tun_name, &config.tun_ip, config.prefix_len)?;
        linux_link_up(&config.tun_name)?;
        linux_enable_ip_forward()?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let adapter = windows_resolve_adapter_name(&config.tun_name)?;
        windows_assign_ip(&adapter, &config.tun_ip, config.prefix_len)?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = config;
        Ok(())
    }
}

pub fn reapply_client_tun(config: &NetConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux_assign_ip(&config.tun_name, &config.tun_ip, config.prefix_len)?;
        linux_link_up(&config.tun_name)?;
        linux_remove_split_default_routes(&config.gateway_ip, &config.tun_name);
        let default = linux_read_default_route()?;
        if let (Some(server_ip), Some(route)) = (config.server_ip, default.as_ref()) {
            linux_add_host_route(server_ip, route)?;
        }
        linux_add_split_default_routes(&config.gateway_ip, &config.tun_name)?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let adapter = windows_resolve_adapter_name(&config.tun_name)?;
        windows_assign_ip(&adapter, &config.tun_ip, config.prefix_len)?;
        windows_remove_split_default_routes(&config.gateway_ip);
        if let Some(route) = windows_read_default_route()? {
            if let Some(server_ip) = config.server_ip {
                windows_add_host_route(server_ip, &route)?;
            }
        }
        windows_add_split_default_routes(&config.gateway_ip)?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = config;
        Ok(())
    }
}

pub async fn update_tun_mtu(iface: &str, mtu: u32) -> Result<()> {
    let safe_mtu = mtu.clamp(576, 9000);

    #[cfg(target_os = "linux")]
    {
        return linux_update_tun_mtu(iface, safe_mtu).await;
    }

    #[cfg(target_os = "windows")]
    {
        return windows_update_tun_mtu(iface, safe_mtu);
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = iface;
        let _ = safe_mtu;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
async fn linux_update_tun_mtu(iface: &str, mtu: u32) -> Result<()> {
    use futures_util::TryStreamExt;
    use rtnetlink::{new_connection, LinkMessageBuilder};

    let (connection, handle, _) =
        new_connection().context("failed to create rtnetlink connection")?;
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name(iface.to_string()).execute();
    let link = links
        .try_next()
        .await
        .context("failed to query link by name")?
        .ok_or_else(|| anyhow!("network interface '{}' not found", iface))?;

    handle
        .link()
        .set(
            LinkMessageBuilder::new()
                .index(link.header.index)
                .mtu(mtu)
                .build(),
        )
        .execute()
        .await
        .with_context(|| format!("failed to update MTU for '{iface}' to {mtu}"))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_update_tun_mtu(iface: &str, mtu: u32) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, GetIpInterfaceEntry, InitializeIpInterfaceEntry,
        SetIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let wide: Vec<u16> = OsStr::new(iface)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut luid = std::mem::zeroed();
        let status = ConvertInterfaceAliasToLuid(windows::core::PCWSTR(wide.as_ptr()), &mut luid);
        if status != NO_ERROR {
            return Err(anyhow!(
                "ConvertInterfaceAliasToLuid failed with status {:?}",
                status
            ));
        }

        for family in [AF_INET, AF_INET6] {
            let mut row = MIB_IPINTERFACE_ROW::default();
            InitializeIpInterfaceEntry(&mut row);
            row.Family = family;
            row.InterfaceLuid = luid;
            let status = GetIpInterfaceEntry(&mut row);
            if status != NO_ERROR {
                continue;
            }
            row.NlMtu = mtu;
            let status = SetIpInterfaceEntry(&mut row);
            if status != NO_ERROR {
                return Err(anyhow!(
                    "SetIpInterfaceEntry failed with status {:?}",
                    status
                ));
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_assign_ip(iface: &str, ip: &str, prefix: u8) -> Result<()> {
    let _ = run_cmd(
        "ip",
        &["addr", "del", &format!("{ip}/{prefix}"), "dev", iface],
    );
    run_cmd(
        "ip",
        &["addr", "add", &format!("{ip}/{prefix}"), "dev", iface],
    )
    .with_context(|| format!("failed to assign {ip}/{prefix} to {iface}"))
}

#[cfg(target_os = "linux")]
fn linux_remove_tun_ip(iface: &str, ip: &str, prefix: u8) {
    let _ = run_cmd(
        "ip",
        &["addr", "del", &format!("{ip}/{prefix}"), "dev", iface],
    );
}

#[cfg(target_os = "linux")]
fn linux_link_up(iface: &str) -> Result<()> {
    run_cmd("ip", &["link", "set", iface, "up"])
        .with_context(|| format!("failed to bring up {iface}"))
}

#[cfg(target_os = "linux")]
fn linux_enable_ip_forward() -> Result<()> {
    match run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
        Ok(_) => Ok(()),
        Err(err) => {
            warn!("sysctl failed ({err}), falling back to /proc");
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")
                .context("failed to enable IP forwarding via /proc")
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_read_default_route() -> Result<Option<DefaultRoute>> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("failed to run 'ip route show default'")?;
    if !output.status.success() {
        return Err(anyhow!("'ip route show default' failed"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.starts_with(&["default"]) {
            continue;
        }
        let gateway = parts
            .iter()
            .position(|part| *part == "via")
            .and_then(|idx| parts.get(idx + 1))
            .ok_or_else(|| anyhow!("default route missing gateway"))?;
        let iface = parts
            .iter()
            .position(|part| *part == "dev")
            .and_then(|idx| parts.get(idx + 1))
            .ok_or_else(|| anyhow!("default route missing device"))?;
        return Ok(Some(DefaultRoute {
            gateway: gateway.parse().context("invalid default gateway")?,
            iface: (*iface).to_string(),
        }));
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
pub fn linux_detect_wan_iface() -> Result<String> {
    if let Some(route) = linux_read_default_route()? {
        return Ok(route.iface);
    }
    Err(anyhow!("cannot detect WAN interface"))
}

#[cfg(target_os = "linux")]
fn linux_add_nat(tun_iface: &str, wan_iface: &str) -> Result<()> {
    let _ = run_cmd("iptables", &["-t", "nat", "-N", NAT_CHAIN]);
    let _ = run_cmd("iptables", &["-N", FILTER_CHAIN]);
    let _ = run_cmd(
        "iptables",
        &["-t", "nat", "-C", "POSTROUTING", "-j", NAT_CHAIN],
    );
    let _ = run_cmd("iptables", &["-C", "FORWARD", "-j", FILTER_CHAIN]);

    let _ = run_cmd(
        "iptables",
        &["-t", "nat", "-I", "POSTROUTING", "1", "-j", NAT_CHAIN],
    );
    let _ = run_cmd("iptables", &["-I", "FORWARD", "1", "-j", FILTER_CHAIN]);
    run_cmd("iptables", &["-t", "nat", "-F", NAT_CHAIN])?;
    run_cmd("iptables", &["-F", FILTER_CHAIN])?;
    run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            NAT_CHAIN,
            "-o",
            wan_iface,
            "-j",
            "MASQUERADE",
        ],
    )?;
    run_cmd(
        "iptables",
        &[
            "-A",
            FILTER_CHAIN,
            "-i",
            tun_iface,
            "-o",
            wan_iface,
            "-j",
            "ACCEPT",
        ],
    )?;
    run_cmd(
        "iptables",
        &[
            "-A",
            FILTER_CHAIN,
            "-i",
            wan_iface,
            "-o",
            tun_iface,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_cleanup_nat(tun_iface: &str, wan_iface: Option<&str>) {
    let _ = wan_iface;
    let _ = tun_iface;
    let _ = run_cmd(
        "iptables",
        &["-t", "nat", "-D", "POSTROUTING", "-j", NAT_CHAIN],
    );
    let _ = run_cmd("iptables", &["-D", "FORWARD", "-j", FILTER_CHAIN]);
    let _ = run_cmd("iptables", &["-t", "nat", "-F", NAT_CHAIN]);
    let _ = run_cmd("iptables", &["-t", "nat", "-X", NAT_CHAIN]);
    let _ = run_cmd("iptables", &["-F", FILTER_CHAIN]);
    let _ = run_cmd("iptables", &["-X", FILTER_CHAIN]);
}

#[cfg(target_os = "linux")]
fn linux_add_host_route(server_ip: IpAddr, route: &DefaultRoute) -> Result<()> {
    let target = host_route_target(server_ip);
    run_cmd(
        "ip",
        &[
            "route",
            "replace",
            &target,
            "via",
            &route.gateway.to_string(),
            "dev",
            &route.iface,
        ],
    )
    .with_context(|| format!("failed to pin route to VPN server {server_ip}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_remove_host_route(server_ip: IpAddr) {
    let _ = run_cmd("ip", &["route", "del", &host_route_target(server_ip)]);
}

#[cfg(target_os = "linux")]
fn linux_add_split_default_routes(gateway: &str, tun_iface: &str) -> Result<()> {
    run_cmd(
        "ip",
        &[
            "route",
            "replace",
            "0.0.0.0/1",
            "via",
            gateway,
            "dev",
            tun_iface,
        ],
    )?;
    run_cmd(
        "ip",
        &[
            "route",
            "replace",
            "128.0.0.0/1",
            "via",
            gateway,
            "dev",
            tun_iface,
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_remove_split_default_routes(gateway: &str, tun_iface: &str) {
    let _ = run_cmd(
        "ip",
        &[
            "route",
            "del",
            "0.0.0.0/1",
            "via",
            gateway,
            "dev",
            tun_iface,
        ],
    );
    let _ = run_cmd(
        "ip",
        &[
            "route",
            "del",
            "128.0.0.0/1",
            "via",
            gateway,
            "dev",
            tun_iface,
        ],
    );
}

#[cfg(target_os = "windows")]
fn windows_resolve_adapter_name(tun_name: &str) -> Result<String> {
    let output = Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
        .context("failed to run 'netsh interface show interface'")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.to_lowercase().contains(&tun_name.to_lowercase()) {
            if let Some(alias) = line.split_whitespace().last() {
                return Ok(alias.to_string());
            }
        }
    }
    Ok(tun_name.to_string())
}

#[cfg(target_os = "windows")]
fn windows_assign_ip(adapter: &str, ip: &str, prefix_len: u8) -> Result<()> {
    let mask = prefix_to_mask(prefix_len);
    let _ = run_cmd(
        "netsh",
        &["interface", "ip", "delete", "address", adapter, ip],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "address",
            adapter,
            "static",
            ip,
            &mask,
        ],
    )
    .with_context(|| format!("failed to assign {ip}/{prefix_len} to '{adapter}'"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_remove_tun_ip(adapter: &str, ip: &str) -> Result<()> {
    let _ = run_cmd(
        "netsh",
        &["interface", "ip", "delete", "address", adapter, ip],
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_read_default_route() -> Result<Option<DefaultRoute>> {
    let output = Command::new("route")
        .args(["print", "-4"])
        .output()
        .context("failed to run 'route print -4'")?;
    if !output.status.success() {
        return Err(anyhow!("'route print -4' failed"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            if let Ok(gateway) = cols[2].parse() {
                return Ok(Some(DefaultRoute {
                    gateway,
                    iface: cols[3].to_string(),
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(target_os = "windows")]
fn windows_add_host_route(server_ip: IpAddr, route: &DefaultRoute) -> Result<()> {
    if !matches!(server_ip, IpAddr::V4(_)) || !matches!(route.gateway, IpAddr::V4(_)) {
        return Err(anyhow!("Windows host-route pinning supports IPv4 only"));
    }
    run_cmd(
        "route",
        &[
            "add",
            &server_ip.to_string(),
            "mask",
            "255.255.255.255",
            &route.gateway.to_string(),
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_remove_host_route(server_ip: IpAddr) {
    let _ = run_cmd("route", &["delete", &server_ip.to_string()]);
}

#[cfg(target_os = "windows")]
fn windows_add_split_default_routes(gateway: &str) -> Result<()> {
    run_cmd("route", &["add", "0.0.0.0", "mask", "128.0.0.0", gateway])?;
    run_cmd("route", &["add", "128.0.0.0", "mask", "128.0.0.0", gateway])?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_remove_split_default_routes(gateway: &str) {
    let _ = run_cmd(
        "route",
        &["delete", "0.0.0.0", "mask", "128.0.0.0", gateway],
    );
    let _ = run_cmd(
        "route",
        &["delete", "128.0.0.0", "mask", "128.0.0.0", gateway],
    );
}

fn host_route_target(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(addr) => format!("{addr}/32"),
        IpAddr::V6(addr) => format!("{addr}/128"),
    }
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute '{program}'"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if output.status.success() {
        Ok(stdout)
    } else {
        Err(anyhow!(
            "command '{} {}' failed (exit {:?}): {}",
            program,
            args.join(" "),
            output.status.code(),
            stderr.trim()
        ))
    }
}

fn prefix_to_mask(prefix_len: u8) -> String {
    let bits = if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let bytes = bits.to_be_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_to_mask() {
        assert_eq!(prefix_to_mask(24), "255.255.255.0");
        assert_eq!(prefix_to_mask(16), "255.255.0.0");
        assert_eq!(prefix_to_mask(0), "0.0.0.0");
    }

    #[test]
    fn test_host_route_target_ipv4() {
        assert_eq!(
            host_route_target(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            "1.2.3.4/32"
        );
    }

    #[test]
    fn test_client_config_defaults() {
        let cfg = NetConfig::client("tun1");
        assert_eq!(cfg.tun_ip, "10.8.0.2");
        assert_eq!(cfg.gateway_ip, "10.8.0.1");
    }

    #[test]
    fn test_server_config_defaults() {
        let cfg = NetConfig::server("tun0");
        assert_eq!(cfg.tun_ip, "10.8.0.1");
        assert_eq!(cfg.prefix_len, 24);
    }
}

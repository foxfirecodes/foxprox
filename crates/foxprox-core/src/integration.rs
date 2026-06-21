use std::net::{IpAddr, SocketAddr};

/// Sandbox-visible network values configured by a setup helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunSetupConfig {
    pub tun_name: String,
    pub sandbox_ip: IpAddr,
    pub broker_ip: IpAddr,
    pub prefix_len: u8,
    pub mtu: u16,
    pub dns_listener: SocketAddr,
    pub http_proxy_listener: SocketAddr,
    pub socks_proxy_listener: SocketAddr,
}

impl TunSetupConfig {
    pub fn alpha_default() -> Self {
        Self {
            tun_name: "foxprox0".to_string(),
            sandbox_ip: "10.0.2.2".parse().expect("static IP valid"),
            broker_ip: "10.0.2.1".parse().expect("static IP valid"),
            prefix_len: 24,
            mtu: 1500,
            dns_listener: "10.0.2.1:53".parse().expect("static socket valid"),
            http_proxy_listener: "10.0.2.1:8080".parse().expect("static socket valid"),
            socks_proxy_listener: "10.0.2.1:1080".parse().expect("static socket valid"),
        }
    }

    pub fn proxy_environment(&self) -> Vec<(String, String)> {
        vec![
            (
                "HTTP_PROXY".to_string(),
                format!("http://{}", self.http_proxy_listener),
            ),
            (
                "HTTPS_PROXY".to_string(),
                format!("http://{}", self.http_proxy_listener),
            ),
            (
                "ALL_PROXY".to_string(),
                format!("socks5://{}", self.socks_proxy_listener),
            ),
            (
                "NO_PROXY".to_string(),
                "localhost,127.0.0.1,::1".to_string(),
            ),
        ]
    }
}

/// Host-to-helper handoff channel description. The concrete fd passing lives in Linux integration crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffConfig {
    pub control_socket_env: String,
    pub close_on_exec: bool,
}

impl Default for HandoffConfig {
    fn default() -> Self {
        Self {
            control_socket_env: "FOXPROX_SETUP_SOCKET".to_string(),
            close_on_exec: true,
        }
    }
}

/// Declarative bwrap-compatible launch plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BwrapLaunchPlan {
    pub bwrap_path: String,
    pub setup_helper_path: String,
    pub target_argv: Vec<String>,
    pub setup: TunSetupConfig,
    pub handoff: HandoffConfig,
    pub bind_dev_net_tun: bool,
}

impl BwrapLaunchPlan {
    pub fn new(
        setup_helper_path: impl Into<String>,
        target_argv: Vec<String>,
    ) -> Result<Self, String> {
        if target_argv.is_empty() {
            return Err("target argv must not be empty".to_string());
        }
        Ok(Self {
            bwrap_path: "bwrap".to_string(),
            setup_helper_path: setup_helper_path.into(),
            target_argv,
            setup: TunSetupConfig::alpha_default(),
            handoff: HandoffConfig::default(),
            bind_dev_net_tun: true,
        })
    }

    /// Render the command argv without invoking bwrap. This makes the contract testable locally.
    pub fn render_argv(&self) -> Vec<String> {
        let mut argv = vec![
            self.bwrap_path.clone(),
            "--unshare-user".to_string(),
            "--unshare-net".to_string(),
            "--cap-add".to_string(),
            "CAP_NET_ADMIN".to_string(),
        ];
        if self.bind_dev_net_tun {
            argv.extend([
                "--dev-bind".to_string(),
                "/dev/net/tun".to_string(),
                "/dev/net/tun".to_string(),
            ]);
        }
        argv.push("--".to_string());
        argv.push(self.setup_helper_path.clone());
        argv.extend([
            "--tun-name".to_string(),
            self.setup.tun_name.clone(),
            "--sandbox-ip".to_string(),
            format!("{}/{}", self.setup.sandbox_ip, self.setup.prefix_len),
            "--broker-ip".to_string(),
            self.setup.broker_ip.to_string(),
            "--mtu".to_string(),
            self.setup.mtu.to_string(),
            "--dns-listener".to_string(),
            self.setup.dns_listener.to_string(),
            "--handoff-env".to_string(),
            self.handoff.control_socket_env.clone(),
            "--".to_string(),
        ]);
        argv.extend(self.target_argv.clone());
        argv
    }

    /// Validate invariants that must hold before a target can be launched safely.
    pub fn validate(&self) -> Result<(), String> {
        if self.setup.mtu < 576 {
            return Err("MTU below IPv4 minimum is unsupported".to_string());
        }
        if !self.bind_dev_net_tun {
            return Err("/dev/net/tun must be available to foxproxsetup".to_string());
        }
        if self.target_argv.is_empty() {
            return Err("target argv must not be empty".to_string());
        }
        Ok(())
    }
}

/// Future foxwrap setup-hook plan. This is rendered separately from bwrap wrapper mode so the lab can
/// verify the fail-closed command contract without depending on a fork existing today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoxwrapSetupHookPlan {
    pub foxwrap_path: String,
    pub setup_helper_host_path: String,
    pub target_argv: Vec<String>,
}

impl FoxwrapSetupHookPlan {
    pub fn render_argv(&self) -> Result<Vec<String>, String> {
        if self.setup_helper_host_path.is_empty() {
            return Err("setup helper path must not be empty".to_string());
        }
        if self.target_argv.is_empty() {
            return Err("target argv must not be empty".to_string());
        }
        let mut argv = vec![
            self.foxwrap_path.clone(),
            "--unshare-user".to_string(),
            "--unshare-net".to_string(),
            "--setup-helper".to_string(),
            self.setup_helper_host_path.clone(),
            "--".to_string(),
        ];
        argv.extend(self.target_argv.clone());
        Ok(argv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bwrap_plan_renders_alpha_wrapper_command_shape() {
        let plan = BwrapLaunchPlan::new(
            "foxproxsetup",
            vec!["curl".to_string(), "http://example.com".to_string()],
        )
        .unwrap();
        plan.validate().unwrap();
        let argv = plan.render_argv();
        assert_eq!(argv[0], "bwrap");
        assert!(argv.windows(2).any(|w| w == ["--cap-add", "CAP_NET_ADMIN"]));
        assert!(argv
            .windows(3)
            .any(|w| w == ["--dev-bind", "/dev/net/tun", "/dev/net/tun"]));
        assert!(argv.contains(&"foxproxsetup".to_string()));
        assert!(argv
            .windows(2)
            .any(|w| w == ["--handoff-env", "FOXPROX_SETUP_SOCKET"]));
    }

    #[test]
    fn proxy_environment_points_at_sandbox_reachable_listeners() {
        let env = TunSetupConfig::alpha_default().proxy_environment();
        assert!(env.contains(&("HTTP_PROXY".to_string(), "http://10.0.2.1:8080".to_string())));
        assert!(env.contains(&(
            "ALL_PROXY".to_string(),
            "socks5://10.0.2.1:1080".to_string()
        )));
    }

    #[test]
    fn invalid_bwrap_plan_fails_before_target_launch() {
        let mut plan = BwrapLaunchPlan::new("foxproxsetup", vec!["true".to_string()]).unwrap();
        plan.bind_dev_net_tun = false;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn foxwrap_hook_plan_renders_future_fail_closed_hook_shape() {
        let plan = FoxwrapSetupHookPlan {
            foxwrap_path: "foxwrap".to_string(),
            setup_helper_host_path: "/usr/libexec/foxproxsetup".to_string(),
            target_argv: vec!["app".to_string()],
        };
        let argv = plan.render_argv().unwrap();
        assert!(argv
            .windows(2)
            .any(|w| w == ["--setup-helper", "/usr/libexec/foxproxsetup"]));
    }
}

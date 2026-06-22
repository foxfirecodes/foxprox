use crate::audit::AuditRecord;
use crate::types::{AuditKind, Decision, DenialReason, Frontend, NetworkEndpoint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSetupConfig {
    pub sandbox_id: String,
    pub tun_name: String,
    pub sandbox_ip: IpAddr,
    pub gateway_ip: IpAddr,
    pub mtu: u16,
    pub broker_dns_ip: IpAddr,
    pub http_proxy_port: u16,
    pub socks_proxy_port: u16,
    pub setup_control_fd: Option<i32>,
}

impl NetworkSetupConfig {
    pub fn alpha_default(sandbox_id: impl Into<String>) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            tun_name: "foxprox0".to_string(),
            sandbox_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            gateway_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)),
            mtu: 1500,
            broker_dns_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 3)),
            http_proxy_port: 3128,
            socks_proxy_port: 1080,
            setup_control_fd: None,
        }
    }

    pub fn proxy_environment(&self) -> ProxyEnvironment {
        let http = format!("http://{}:{}", self.gateway_ip, self.http_proxy_port);
        let socks = format!("socks5h://{}:{}", self.gateway_ip, self.socks_proxy_port);
        ProxyEnvironment {
            http_proxy: http.clone(),
            https_proxy: http,
            all_proxy: socks,
            no_proxy: "localhost,127.0.0.1,::1".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEnvironment {
    pub http_proxy: String,
    pub https_proxy: String,
    pub all_proxy: String,
    pub no_proxy: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BwrapSetupPlan {
    pub config: NetworkSetupConfig,
    pub bwrap_args: Vec<String>,
    pub setup_command: Vec<String>,
    pub proxy_environment: ProxyEnvironment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupHelperPlan {
    pub config: NetworkSetupConfig,
    pub steps: Vec<SetupHelperStep>,
    pub proxy_environment: ProxyEnvironment,
    pub target_command: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupHelperStep {
    pub name: String,
    pub command: Vec<String>,
    pub evidence: BTreeMap<String, String>,
}

impl SetupHelperStep {
    fn new(name: impl Into<String>, command: Vec<String>) -> Self {
        Self {
            name: name.into(),
            command,
            evidence: BTreeMap::new(),
        }
    }

    fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}

impl SetupHelperPlan {
    pub fn new(config: NetworkSetupConfig, target_command: &[String]) -> Self {
        let prefix_len = 24u8;
        let mut steps = vec![
            SetupHelperStep::new(
                "create_tun",
                vec![
                    "ip".to_string(),
                    "tuntap".to_string(),
                    "add".to_string(),
                    "dev".to_string(),
                    config.tun_name.clone(),
                    "mode".to_string(),
                    "tun".to_string(),
                ],
            )
            .with_evidence("requires_capability", "CAP_NET_ADMIN"),
            SetupHelperStep::new(
                "assign_tun_address",
                vec![
                    "ip".to_string(),
                    "addr".to_string(),
                    "add".to_string(),
                    format!("{}/{}", config.sandbox_ip, prefix_len),
                    "dev".to_string(),
                    config.tun_name.clone(),
                ],
            ),
            SetupHelperStep::new(
                "set_tun_mtu_up",
                vec![
                    "ip".to_string(),
                    "link".to_string(),
                    "set".to_string(),
                    "dev".to_string(),
                    config.tun_name.clone(),
                    "mtu".to_string(),
                    config.mtu.to_string(),
                    "up".to_string(),
                ],
            ),
            SetupHelperStep::new(
                "configure_default_route",
                vec![
                    "ip".to_string(),
                    "route".to_string(),
                    "add".to_string(),
                    "default".to_string(),
                    "via".to_string(),
                    config.gateway_ip.to_string(),
                    "dev".to_string(),
                    config.tun_name.clone(),
                ],
            ),
            SetupHelperStep::new(
                "configure_dns",
                vec![
                    "write-resolv-conf".to_string(),
                    format!("nameserver {}", config.broker_dns_ip),
                ],
            )
            .with_evidence("dns_mode", "broker_dns"),
            SetupHelperStep::new(
                "configure_proxy_reachability",
                vec![
                    "export-proxy-env".to_string(),
                    config.proxy_environment().http_proxy,
                    config.proxy_environment().all_proxy,
                ],
            ),
        ];
        if let Some(fd) = config.setup_control_fd {
            steps.push(
                SetupHelperStep::new(
                    "handoff_tun_fd",
                    vec![
                        "send-fd".to_string(),
                        fd.to_string(),
                        config.tun_name.clone(),
                    ],
                )
                .with_evidence("setup_control_fd", fd.to_string()),
            );
        }
        steps.extend([
            SetupHelperStep::new("close_setup_fds", vec!["close-setup-fds".to_string()])
                .with_evidence("closes_setup_only_fds", "true"),
            SetupHelperStep::new(
                "drop_setup_capability",
                vec!["capsh".to_string(), "--drop=cap_net_admin".to_string()],
            )
            .with_evidence("dropped_capability", "CAP_NET_ADMIN"),
        ]);
        Self {
            proxy_environment: config.proxy_environment(),
            config,
            steps,
            target_command: target_command.to_vec(),
        }
    }

    pub fn audit_record(&self) -> AuditRecord {
        AuditRecord::new(AuditKind::TunConfigured, self.config.sandbox_id.clone())
            .with_frontend(Frontend::Setup)
            .with_destination(NetworkEndpoint::ip(self.config.gateway_ip))
            .with_decision(Decision::Allow, None)
            .with_detail("setup_helper", "foxproxsetup")
            .with_detail("tun_name", self.config.tun_name.clone())
            .with_detail("mtu", self.config.mtu.to_string())
            .with_detail("steps", self.steps.len().to_string())
            .with_detail("target_argc", self.target_command.len().to_string())
            .with_detail("drops_capability", "CAP_NET_ADMIN")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupExecutionReport {
    pub completed_steps: Vec<String>,
    pub failed_step: Option<String>,
    pub failed_step_index: Option<usize>,
    pub target_exec_ready: bool,
    pub audit: AuditRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupStepRunError {
    pub detail: String,
}

impl SetupStepRunError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

pub trait SetupStepRunner {
    fn run_setup_step(&mut self, step: &SetupHelperStep) -> Result<(), SetupStepRunError>;
}

impl SetupHelperPlan {
    pub fn execute_with<R: SetupStepRunner>(&self, runner: &mut R) -> SetupExecutionReport {
        let mut completed_steps = Vec::new();
        for (index, step) in self.steps.iter().enumerate() {
            if let Err(error) = runner.run_setup_step(step) {
                let audit =
                    AuditRecord::new(AuditKind::BrokerError, self.config.sandbox_id.clone())
                        .with_frontend(Frontend::Setup)
                        .with_decision(Decision::FailClosed, Some(DenialReason::SetupFailed))
                        .with_detail("setup_step", step.name.clone())
                        .with_detail("setup_step_index", index.to_string())
                        .with_detail("setup_error", error.detail)
                        .with_detail("completed_steps", completed_steps.len().to_string());
                return SetupExecutionReport {
                    completed_steps,
                    failed_step: Some(step.name.clone()),
                    failed_step_index: Some(index),
                    target_exec_ready: false,
                    audit,
                };
            }
            completed_steps.push(step.name.clone());
        }
        let audit = self
            .audit_record()
            .with_detail("executed_steps", completed_steps.len().to_string())
            .with_detail("target_exec_ready", "true");
        SetupExecutionReport {
            completed_steps,
            failed_step: None,
            failed_step_index: None,
            target_exec_ready: true,
            audit,
        }
    }
}

impl BwrapSetupPlan {
    pub fn new(config: NetworkSetupConfig, target_command: &[String]) -> Self {
        let mut bwrap_args = vec![
            "--unshare-user".to_string(),
            "--unshare-net".to_string(),
            "--cap-add".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--dev-bind".to_string(),
            "/dev/net/tun".to_string(),
            "/dev/net/tun".to_string(),
        ];
        if let Some(fd) = config.setup_control_fd {
            bwrap_args.extend(["--sync-fd".to_string(), fd.to_string()]);
        }

        let mut setup_command = vec![
            "foxproxsetup".to_string(),
            "--sandbox-id".to_string(),
            config.sandbox_id.clone(),
            "--tun-name".to_string(),
            config.tun_name.clone(),
            "--sandbox-ip".to_string(),
            config.sandbox_ip.to_string(),
            "--gateway-ip".to_string(),
            config.gateway_ip.to_string(),
            "--mtu".to_string(),
            config.mtu.to_string(),
            "--dns".to_string(),
            config.broker_dns_ip.to_string(),
            "--http-proxy".to_string(),
            format!("{}:{}", config.gateway_ip, config.http_proxy_port),
            "--socks-proxy".to_string(),
            format!("{}:{}", config.gateway_ip, config.socks_proxy_port),
        ];
        if let Some(fd) = config.setup_control_fd {
            setup_command.extend(["--setup-control-fd".to_string(), fd.to_string()]);
        }
        setup_command.extend([
            "--drop-cap".to_string(),
            "CAP_NET_ADMIN".to_string(),
            "--".to_string(),
        ]);
        setup_command.extend(target_command.iter().cloned());

        let proxy_environment = config.proxy_environment();
        Self {
            config,
            bwrap_args,
            setup_command,
            proxy_environment,
        }
    }

    pub fn audit_record(&self) -> AuditRecord {
        AuditRecord::new(AuditKind::SetupPlanCreated, self.config.sandbox_id.clone())
            .with_frontend(Frontend::Setup)
            .with_destination(NetworkEndpoint::ip(self.config.gateway_ip))
            .with_decision(Decision::Allow, None)
            .with_detail("tun_name", self.config.tun_name.clone())
            .with_detail("mtu", self.config.mtu.to_string())
            .with_detail("broker_dns_ip", self.config.broker_dns_ip.to_string())
            .with_detail("requires_capability", "CAP_NET_ADMIN")
            .with_detail("setup_helper", "foxproxsetup")
    }

    pub fn full_command(&self) -> Vec<String> {
        let mut command = vec!["bwrap".to_string()];
        command.extend(self.bwrap_args.clone());
        command.extend(self.setup_command.clone());
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn bwrap_plan_contains_alpha_network_setup_contract() {
        let target = vec!["curl".to_string(), "http://example.com".to_string()];
        let plan = BwrapSetupPlan::new(NetworkSetupConfig::alpha_default("s1"), &target);
        let full = plan.full_command();

        assert!(full.contains(&"--unshare-user".to_string()));
        assert!(full.contains(&"--unshare-net".to_string()));
        assert!(full.windows(2).any(|w| w == ["--cap-add", "CAP_NET_ADMIN"]));
        assert!(full
            .windows(3)
            .any(|w| w == ["--dev-bind", "/dev/net/tun", "/dev/net/tun"]));
        assert!(full.contains(&"foxproxsetup".to_string()));
        assert!(full
            .windows(2)
            .any(|w| w == ["--drop-cap", "CAP_NET_ADMIN"]));
        assert!(full.ends_with(&target));
    }

    #[test]
    fn setup_helper_plan_contains_network_setup_and_exec_contract() {
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_fd = Some(9);
        let plan = SetupHelperPlan::new(
            config,
            &["curl".to_string(), "http://example.com".to_string()],
        );
        let step_names: Vec<_> = plan.steps.iter().map(|step| step.name.as_str()).collect();
        assert_eq!(
            step_names,
            vec![
                "create_tun",
                "assign_tun_address",
                "set_tun_mtu_up",
                "configure_default_route",
                "configure_dns",
                "configure_proxy_reachability",
                "handoff_tun_fd",
                "close_setup_fds",
                "drop_setup_capability",
            ]
        );
        assert!(plan.steps[0]
            .command
            .windows(3)
            .any(|w| w == ["dev", "foxprox0", "mode"]));
        assert_eq!(plan.steps[4].evidence["dns_mode"], "broker_dns");
        assert_eq!(plan.steps[6].evidence["setup_control_fd"], "9");
        assert_eq!(plan.steps[7].evidence["closes_setup_only_fds"], "true");
        assert_eq!(
            plan.steps[8].evidence["dropped_capability"],
            "CAP_NET_ADMIN"
        );
        assert_eq!(plan.target_command.len(), 2);
    }

    #[test]
    fn setup_helper_plan_audit_is_structured() {
        let plan = SetupHelperPlan::new(
            NetworkSetupConfig::alpha_default("s1"),
            &["true".to_string()],
        );
        let audit = plan.audit_record();
        assert_eq!(audit.kind, AuditKind::TunConfigured);
        assert_eq!(audit.frontend, Some(Frontend::Setup));
        assert_eq!(audit.details["setup_helper"], "foxproxsetup");
        assert_eq!(audit.details["drops_capability"], "CAP_NET_ADMIN");
        assert_eq!(audit.details["steps"], "8");
        assert_eq!(audit.details["target_argc"], "1");
    }

    #[derive(Default)]
    struct ScriptedSetupRunner {
        ran_steps: Vec<String>,
        fail_step: Option<String>,
    }

    impl SetupStepRunner for ScriptedSetupRunner {
        fn run_setup_step(&mut self, step: &SetupHelperStep) -> Result<(), SetupStepRunError> {
            if self.fail_step.as_deref() == Some(step.name.as_str()) {
                return Err(SetupStepRunError::new(format!("{} failed", step.name)));
            }
            self.ran_steps.push(step.name.clone());
            Ok(())
        }
    }

    #[test]
    fn setup_execution_harness_records_successful_steps() {
        let plan = SetupHelperPlan::new(
            NetworkSetupConfig::alpha_default("s1"),
            &["true".to_string()],
        );
        let mut runner = ScriptedSetupRunner::default();
        let report = plan.execute_with(&mut runner);

        assert!(report.failed_step.is_none());
        assert!(report.target_exec_ready);
        assert_eq!(report.completed_steps, runner.ran_steps);
        assert_eq!(
            report.completed_steps.last().unwrap(),
            "drop_setup_capability"
        );
        assert_eq!(report.audit.kind, AuditKind::TunConfigured);
        assert_eq!(report.audit.decision, Some(Decision::Allow));
        assert_eq!(report.audit.details["executed_steps"], "8");
        assert_eq!(report.audit.details["target_exec_ready"], "true");
    }

    #[test]
    fn setup_execution_harness_stops_and_audits_failed_step() {
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_fd = Some(9);
        let plan = SetupHelperPlan::new(config, &["true".to_string()]);
        let mut runner = ScriptedSetupRunner {
            fail_step: Some("configure_dns".to_string()),
            ..ScriptedSetupRunner::default()
        };
        let report = plan.execute_with(&mut runner);

        assert_eq!(report.failed_step.as_deref(), Some("configure_dns"));
        assert_eq!(report.failed_step_index, Some(4));
        assert!(!report.target_exec_ready);
        assert_eq!(
            runner.ran_steps,
            vec![
                "create_tun".to_string(),
                "assign_tun_address".to_string(),
                "set_tun_mtu_up".to_string(),
                "configure_default_route".to_string(),
            ]
        );
        assert_eq!(report.completed_steps, runner.ran_steps);
        assert_eq!(report.audit.kind, AuditKind::BrokerError);
        assert_eq!(report.audit.decision, Some(Decision::FailClosed));
        assert_eq!(report.audit.reason, Some(DenialReason::SetupFailed));
        assert_eq!(report.audit.details["setup_step"], "configure_dns");
        assert_eq!(report.audit.details["setup_step_index"], "4");
        assert_eq!(report.audit.details["completed_steps"], "4");
    }

    #[test]
    fn bwrap_plan_passes_setup_control_fd_to_helper() {
        let mut config = NetworkSetupConfig::alpha_default("s1");
        config.setup_control_fd = Some(9);
        let plan = BwrapSetupPlan::new(config, &["true".to_string()]);
        assert!(plan.bwrap_args.windows(2).any(|w| w == ["--sync-fd", "9"]));
        assert!(plan
            .setup_command
            .windows(2)
            .any(|w| w == ["--setup-control-fd", "9"]));
    }

    #[test]
    fn proxy_environment_points_at_sandbox_reachable_gateway() {
        let config = NetworkSetupConfig::alpha_default("s1");
        let env = config.proxy_environment();
        assert_eq!(env.http_proxy, "http://10.0.2.2:3128");
        assert_eq!(env.https_proxy, "http://10.0.2.2:3128");
        assert_eq!(env.all_proxy, "socks5h://10.0.2.2:1080");
    }

    #[test]
    fn setup_plan_audit_is_structured() {
        let plan = BwrapSetupPlan::new(
            NetworkSetupConfig::alpha_default("s1"),
            &["true".to_string()],
        );
        let audit = plan.audit_record();
        assert_eq!(audit.kind, AuditKind::SetupPlanCreated);
        assert_eq!(audit.frontend, Some(Frontend::Setup));
        assert_eq!(audit.details["setup_helper"], "foxproxsetup");
        assert_eq!(audit.details["requires_capability"], "CAP_NET_ADMIN");
    }
}

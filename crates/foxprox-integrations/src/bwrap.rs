#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwrapSetupConfig {
    pub bwrap_program: String,
    pub setup_helper: String,
    pub target_args: Vec<String>,
    pub proxy_environment: Option<ProxyEnvironment>,
}

impl BwrapSetupConfig {
    pub fn new(
        bwrap_program: impl Into<String>,
        setup_helper: impl Into<String>,
        target_args: Vec<String>,
    ) -> Self {
        Self {
            bwrap_program: bwrap_program.into(),
            setup_helper: setup_helper.into(),
            target_args,
            proxy_environment: None,
        }
    }

    pub fn with_proxy_environment(mut self, proxy_environment: ProxyEnvironment) -> Self {
        self.proxy_environment = Some(proxy_environment);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEnvironment {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub all_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

impl ProxyEnvironment {
    pub fn new() -> Self {
        Self {
            http_proxy: None,
            https_proxy: None,
            all_proxy: None,
            no_proxy: None,
        }
    }

    pub fn with_http_proxy(mut self, value: impl Into<String>) -> Self {
        self.http_proxy = Some(value.into());
        self
    }

    pub fn with_https_proxy(mut self, value: impl Into<String>) -> Self {
        self.https_proxy = Some(value.into());
        self
    }

    pub fn with_all_proxy(mut self, value: impl Into<String>) -> Self {
        self.all_proxy = Some(value.into());
        self
    }

    pub fn with_no_proxy(mut self, value: impl Into<String>) -> Self {
        self.no_proxy = Some(value.into());
        self
    }

    fn validate(&self) -> Result<(), SetupBuildError> {
        for value in [
            &self.http_proxy,
            &self.https_proxy,
            &self.all_proxy,
            &self.no_proxy,
        ]
        .into_iter()
        .flatten()
        {
            validate_arg(value).map_err(|_| SetupBuildError::InvalidProxyEnvironment)?;
        }
        Ok(())
    }

    fn pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(value) = &self.http_proxy {
            pairs.push(("HTTP_PROXY".into(), value.clone()));
        }
        if let Some(value) = &self.https_proxy {
            pairs.push(("HTTPS_PROXY".into(), value.clone()));
        }
        if let Some(value) = &self.all_proxy {
            pairs.push(("ALL_PROXY".into(), value.clone()));
        }
        if let Some(value) = &self.no_proxy {
            pairs.push(("NO_PROXY".into(), value.clone()));
        }
        pairs
    }
}

impl Default for ProxyEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BwrapSetupCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SetupBuildError {
    EmptyBwrapProgram,
    EmptySetupHelper,
    EmptyTarget,
    InvalidArgument,
    InvalidProxyEnvironment,
}

pub fn build_bwrap_setup_command(
    config: BwrapSetupConfig,
) -> Result<BwrapSetupCommand, SetupBuildError> {
    validate_arg(&config.bwrap_program).map_err(|_| SetupBuildError::EmptyBwrapProgram)?;
    validate_arg(&config.setup_helper).map_err(|_| SetupBuildError::EmptySetupHelper)?;
    if config.target_args.is_empty() {
        return Err(SetupBuildError::EmptyTarget);
    }
    for arg in &config.target_args {
        validate_arg(arg).map_err(|_| SetupBuildError::InvalidArgument)?;
    }
    if let Some(proxy_environment) = &config.proxy_environment {
        proxy_environment.validate()?;
    }

    let mut args = vec![
        "--unshare-user".to_string(),
        "--unshare-net".to_string(),
        "--cap-add".to_string(),
        "CAP_NET_ADMIN".to_string(),
        "--dev-bind".to_string(),
        "/dev/net/tun".to_string(),
        "/dev/net/tun".to_string(),
        "--".to_string(),
        config.setup_helper,
        "--".to_string(),
    ];
    args.extend(config.target_args);

    Ok(BwrapSetupCommand {
        program: config.bwrap_program,
        args,
        env: config
            .proxy_environment
            .map(|environment| environment.pairs())
            .unwrap_or_default(),
    })
}

fn validate_arg(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.contains('\0') {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bwrap_setup_command_includes_required_network_setup_boundary() {
        let command = build_bwrap_setup_command(BwrapSetupConfig::new(
            "bwrap",
            "foxproxsetup",
            vec!["curl".into(), "https://example.com".into()],
        ))
        .unwrap();

        assert_eq!(command.program, "bwrap");
        assert!(command.args.contains(&"--unshare-user".into()));
        assert!(command.args.contains(&"--unshare-net".into()));
        assert_eq!(
            command
                .args
                .windows(2)
                .filter(|window| *window == ["--cap-add", "CAP_NET_ADMIN"])
                .count(),
            1
        );
        assert_eq!(
            command
                .args
                .windows(3)
                .filter(|window| *window == ["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
                .count(),
            1
        );
        assert!(command.args.ends_with(&[
            "--".into(),
            "foxproxsetup".into(),
            "--".into(),
            "curl".into(),
            "https://example.com".into(),
        ]));
    }

    #[test]
    fn bwrap_setup_command_rejects_ambiguous_or_empty_argv() {
        assert_eq!(
            build_bwrap_setup_command(BwrapSetupConfig::new(
                "",
                "foxproxsetup",
                vec!["true".into()],
            )),
            Err(SetupBuildError::EmptyBwrapProgram)
        );
        assert_eq!(
            build_bwrap_setup_command(BwrapSetupConfig::new("bwrap", "", vec!["true".into()])),
            Err(SetupBuildError::EmptySetupHelper)
        );
        assert_eq!(
            build_bwrap_setup_command(BwrapSetupConfig::new("bwrap", "foxproxsetup", Vec::new())),
            Err(SetupBuildError::EmptyTarget)
        );
        assert_eq!(
            build_bwrap_setup_command(BwrapSetupConfig::new(
                "bwrap",
                "foxproxsetup",
                vec!["bad\0arg".into()],
            )),
            Err(SetupBuildError::InvalidArgument)
        );
    }

    #[test]
    fn proxy_environment_is_deterministic_and_validated() {
        let proxy_environment = ProxyEnvironment::new()
            .with_http_proxy("http://10.0.2.2:8080")
            .with_https_proxy("http://10.0.2.2:8080")
            .with_all_proxy("socks5://10.0.2.2:1080")
            .with_no_proxy("localhost,127.0.0.1");
        let command = build_bwrap_setup_command(
            BwrapSetupConfig::new("bwrap", "foxproxsetup", vec!["true".into()])
                .with_proxy_environment(proxy_environment),
        )
        .unwrap();

        assert_eq!(
            command.env,
            vec![
                ("HTTP_PROXY".into(), "http://10.0.2.2:8080".into()),
                ("HTTPS_PROXY".into(), "http://10.0.2.2:8080".into()),
                ("ALL_PROXY".into(), "socks5://10.0.2.2:1080".into()),
                ("NO_PROXY".into(), "localhost,127.0.0.1".into()),
            ]
        );

        let bad_proxy_environment = ProxyEnvironment::new().with_http_proxy("bad\0proxy");
        assert_eq!(
            build_bwrap_setup_command(
                BwrapSetupConfig::new("bwrap", "foxproxsetup", vec!["true".into()])
                    .with_proxy_environment(bad_proxy_environment),
            ),
            Err(SetupBuildError::InvalidProxyEnvironment)
        );
    }
}

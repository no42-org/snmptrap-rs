use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    /// CLI usage / argument-parsing failure. Produces exit code 2 (matches POSIX getopts convention).
    Usage(String),
    /// Raw socket creation or send was denied due to missing capabilities (Linux EPERM/EACCES,
    /// macOS lack of root). The display impl emits the structured remediation message.
    RawSocketDenied {
        platform: Platform,
        underlying: io::Error,
    },
    /// Spoofing requested but the platform doesn't expose raw IPv4 + IP_HDRINCL.
    Unsupported(String),
    /// Routing/EMSGSIZE/etc. — anything network-layer that is NOT a capability problem.
    Routing(io::Error),
    /// SNMP encoding failure.
    Encode(String),
    /// Catch-all for unexpected I/O errors.
    Other(io::Error),
}

#[derive(Debug, Clone, Copy)]
pub enum Platform {
    Linux,
    Macos,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Other
        }
    }
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            _ => 1,
        }
    }

    pub fn report_to_stderr(&self) {
        eprintln!("error: {self}");
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) => write!(f, "{msg}"),
            Self::RawSocketDenied {
                platform,
                underlying,
            } => {
                writeln!(
                    f,
                    "--src-addr requires raw IP socket capability, which this binary does not have."
                )?;
                match platform {
                    Platform::Linux => {
                        writeln!(f)?;
                        writeln!(f, "On Linux, grant it once with:")?;
                        writeln!(f)?;
                        writeln!(
                            f,
                            "    sudo setcap cap_net_raw+ep \"$(command -v snmptrap-rs)\""
                        )?;
                        writeln!(f)?;
                        writeln!(f, "Or run as root.")?;
                    }
                    Platform::Macos => {
                        writeln!(f)?;
                        writeln!(
                            f,
                            "On macOS, run as root (sudo). macOS has no per-binary capability grant."
                        )?;
                    }
                    Platform::Other => {
                        writeln!(f)?;
                        writeln!(f, "On this platform, run as root.")?;
                    }
                }
                write!(f, "(raw socket open failed: {underlying})")
            }
            Self::Unsupported(msg) => write!(f, "{msg}"),
            Self::Routing(io) => write!(f, "{io}"),
            Self::Encode(msg) => write!(f, "encoding error: {msg}"),
            Self::Other(io) => write!(f, "{io}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Other(err)
    }
}

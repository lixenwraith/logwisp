#!/bin/sh
# Deploys one LogWisp node: an edge (log files -> chain), an aggregator (chain
# -> files, streams) or a standalone node (log files -> files, streams), as a
# docker or podman container, a systemd or FreeBSD rc.d service, or a plain
# configuration. Asks for what the flags leave open; -h lists the flags and
# doc/deployment.md walks through the scenarios.

set -u
set -f # globs such as *.log are values here, never file names
umask 022

PROG=${0##*/}
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) || exit 1
REPO=${SCRIPT_DIR%/*}
PACKAGE_DIR=$SCRIPT_DIR/package
NL='
'
OIFS=$IFS
IMAGE_USER=65532:65532
PKG_UNIT=/usr/lib/systemd/system/logwisp.service # a package's, used as it is
HOME_DIR=${HOME:-$PWD} # keeps keys and passwords out of a checkout run from its root

ROLE='' RUNTIME='' ENGINE='' TARGET_OS='' NAME='' CONF_DIR='' JAIL=''
LOG_DIRS='' LOG_PATTERN='' FROM='' LOG_GROUP=''
CHAIN='' AGGREGATOR='' CHAIN_PORT='' NODE='' LISTEN=''
FILE_DIR='' FILE_NAME='' HTTP_PORT='' TCP_PORT='' FORMAT=''
TLS='' CERT_FILE='' KEY_FILE='' CA_FILE='' SERVER_NAME=''
AUTH='' ALLOW='' USERNAME='' PASSWORD_FILE='' ADD_USERS=''
SINK_AUTH='' SINK_ALLOW='' ADD_VIEWERS='' SECRETS_DIR=''
IMAGE='' BUILD='' BUILD_CA='' BUILD_FLAGS='' NETWORK='' BIN=''
START='' FORCE='' YES=0 DRY_RUN=0

usage() {
	cat <<EOF
Usage: $PROG [options]

Writes a LogWisp configuration for one node and deploys it. Without --yes it
asks for every value the options leave open, with inline menus; with --yes it
takes the defaults and fails on a missing required value.

General
  -y, --yes               no prompts: take defaults, fail on missing values
  -n, --dry-run           print the configuration and commands, change nothing
  -h, --help              this text
  --role ROLE             edge | aggregator | standalone
  --runtime RUNTIME       docker | podman | native | manual (configuration only)
  --engine ENGINE         docker | podman, for --runtime docker (default docker)
  --os OS                 linux | freebsd, the target (default: this host)
  --force                 overwrite an existing configuration, replace a container
  --start, --no-start     start the container or service (default: start)

Sources (edge, standalone)
  --log-dir DIR           directory to tail, not recursive; repeatable
  --log-pattern GLOB      files to tail in each directory (default *.log)
  --from end|start        where a newly found file is read from (default end)
  --log-group GROUP       group allowed to read the logs, given to the service

Chain (edge dials, aggregator listens)
  --chain tcp|http        transport (default tcp)
  --aggregator HOST       edge: the aggregator's address
  --chain-port PORT       default 9440 (tcp) or 9441 (http)
  --node LABEL            edge: origin label (default: short host name)
  --listen ADDR           listeners' address (default 0.0.0.0; for a container
                          on a bridge network, the address its ports publish on)

Outputs (aggregator, standalone)
  --file-dir DIR          write rotating files there
  --file-name NAME        file name stem (default logwisp)
  --http-port PORT        serve an SSE stream at /stream and status at /status
  --tcp-port PORT         serve a plain TCP stream
  --format raw|txt|json   entry format (default txt)

TLS (this script creates no certificates: doc/security.md#enabling-mtls)
  --tls, --no-tls         TLS on every network link of the node
  --cert-file FILE        this node's certificate: listeners, and edges under mtls
  --key-file FILE         its private key
  --ca-file FILE          CA bundle: an edge verifies the aggregator with it, a
                          listener the client certificates
  --server-name NAME      edge: name the aggregator's certificate must carry

Authentication (needs TLS; without --auth or --sink-auth the flags below imply
their mode, and under --yes one that does not apply stops the run)
  --auth none|mtls|scram  the chain link
  --allow ID              mtls certificate CN; an edge pins the aggregator, an
                          aggregator admits edges; repeatable (none: any the CA issued)
  --username NAME         edge, scram (default: the password file's name
                          without .pass, as the aggregator wrote it)
  --password-file FILE    edge, scram: the password the aggregator generated
  --add-user NAME         aggregator, scram: create or update an edge's user; repeatable
  --sink-auth none|mtls|scram  the http and tcp outputs
  --sink-allow ID         mtls viewer CN; repeatable
  --add-viewer NAME       scram viewer; repeatable
  --secrets-dir DIR       generated passwords, absolute (default ~/logwisp-secrets)

Containers (Linux)
  --name NAME             container name (default logwisp-ROLE)
  --config-dir DIR        host directory mounted at /etc/logwisp (default
                          /etc/logwisp/NAME); --runtime manual writes there
                          (default ~/logwisp-ROLE)
  --image IMAGE           default logwisp:dev, what "make image" builds
  --build, --no-build     build IMAGE from this repository (native: make build)
  --build-ca FILE         CA of an HTTPS-intercepting proxy, for the build only
  --build-flags FLAGS     extra build flags, split on spaces ("--network host")
  --network NET           container network, created when missing; "host"
                          publishes nothing and listens on --listen

Native services
  --bin FILE              lw binary to install (default: the installed one, else bin/lw)
  --jail NAME             FreeBSD: install into this running jail through jexec
  --package-dir DIR       service files (default deploy/package)

EOF
	not_covered ''
}

not_covered() { # PREFIX
	sed "s/^/$1/" <<'EOF'
Not covered by this script; edit the generated configuration instead
(config/logwisp.toml documents every key):
- filters, rate limits, heartbeat, formatter flags and timestamp layouts
- more than one pipeline; both chain transports, or a further hop, on one node
- proxy mode: browser logins through a TLS-terminating proxy (trusted_proxies)
- network ACLs: not implemented in LogWisp yet
- mtls identities other than the certificate CN; node_binding other than force
- creating certificates: openssl or your PKI (doc/security.md#enabling-mtls)
- several native instances on one host: use one per host or jail
EOF
}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 1; }
warn() { printf '%s: warning: %s\n' "$PROG" "$*" >&2; }
note() { printf '%s\n' "$*"; }

add_item() { if [ -z "$1" ]; then printf '%s' "$2"; else printf '%s\n%s' "$1" "$2"; fi; }

shquote() {
	case $1 in
	'') printf "''" ;;
	*[!A-Za-z0-9_./:=,@%+-]*) printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")" ;;
	*) printf '%s' "$1" ;;
	esac
}

tq() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

tlist() { # newline-separated list -> TOML array
	_tl=''
	IFS=$NL
	for _i in $1; do _tl="$_tl${_tl:+, }$(tq "$_i")"; done
	IFS=$OIFS
	printf '[%s]' "$_tl"
}

urlhost() { case $1 in *:*) printf '[%s]' "$1" ;; *) printf '%s' "$1" ;; esac; }
# in a URL a zone's % is escaped as %25 (RFC 6874)
urihost() { case $1 in *%*) urlhost "${1%%\%*}%25${1#*%}" ;; *) urlhost "$1" ;; esac; }

# --- commands: printed, and run unless --dry-run ---

show_cmd() { # a long command breaks before each option up to its first operand
	printf '+'
	_brk='' _n=0 _prev=-
	[ $# -le 12 ] || _brk=yes
	for _a in "$@"; do
		_n=$((_n + 1))
		_b=$_brk
		case $_a in -*) ;; *) case $_prev in -*) _b='' ;; *) [ "$_n" -le 2 ] || _brk='' ;; esac ;; esac
		[ "$_b" != yes ] || [ "$_n" -le 2 ] || printf ' \\\n   '
		printf ' %s' "$(shquote "$_a")"
		_prev=$_a
	done
}

run() {
	show_cmd "$@"
	printf '\n'
	[ "$DRY_RUN" = 1 ] || "$@"
}

run_in() { # FILE COMMAND...: COMMAND reads FILE on stdin
	_in=$1
	shift
	show_cmd "$@"
	printf ' < %s\n' "$(shquote "$_in")"
	[ "$DRY_RUN" = 1 ] || "$@" <"$_in"
}

# trun runs inside the target jail when there is one; tprobe also, unprinted.
trun() { if [ -n "$JAIL" ]; then run jexec "$JAIL" "$@"; else run "$@"; fi; }
tprobe() { if [ -n "$JAIL" ]; then jexec "$JAIL" "$@"; else "$@"; fi; }

# put_file writes stdin, or SOURCE, to PATH in the target: a jail's own
# symlinks then resolve inside the jail, never on the host.
put_file() { # PATH MODE [SOURCE]
	if [ "$DRY_RUN" = 1 ]; then
		if [ -n "${3:-}" ]; then
			printf '+ copy %s to %s (mode %s)%s\n' "$(shquote "$3")" "$(shquote "$1")" "$2" "${JAIL:+ in jail $JAIL}"
		else
			printf '+ write %s (mode %s)%s:\n' "$(shquote "$1")" "$2" "${JAIL:+ in jail $JAIL}"
			sed 's/^/    | /'
		fi
		return 0
	fi
	[ -z "${3:-}" ] || { put_file "$1" "$2" <"$3"; return; }
	# shellcheck disable=SC2016 # expanded by the inner shell
	tprobe /bin/sh -c 'umask 077 && t=$1.lw-deploy.$$ &&
		{ cat >"$t" && chmod "$2" "$t" && mv -f "$t" "$1" || { rm -f "$t"; exit 1; }; }' put_file "$1" "$2" ||
		die "cannot write $1${JAIL:+ in jail $JAIL}"
	note "wrote $1${JAIL:+ in jail $JAIL}"
}

# --- prompts: a value given as a flag is validated, never asked again ---

prompt_line() { # PROMPT DEFAULT -> REPLY
	if [ -n "$2" ]; then printf '%s [%s]: ' "$1" "$2" >&2; else printf '%s: ' "$1" >&2; fi
	IFS= read -r REPLY || die "input ended"
}

ask() { # VAR FLAG PROMPT DEFAULT [VALIDATOR]
	_var=$1 _flag=$2 _prompt=$3 _def=$4 _check=${5:-}
	eval "_val=\$$_var"
	if [ -z "$_val" ] && [ "$INTERACTIVE" = 0 ]; then
		[ -n "$_def" ] || die "missing value: $_flag"
		_val=$_def
	fi
	while [ -z "$_val" ] || { [ -n "$_check" ] && ! "$_check" "$_val"; }; do
		[ "$INTERACTIVE" = 1 ] || die "invalid $_flag: $_val"
		prompt_line "$_prompt" "$_def"
		_val=${REPLY:-$_def}
	done
	eval "$_var=\$_val"
}

ask_opt() { # VAR FLAG PROMPT [VALIDATOR]: empty is an answer
	_var=$1 _flag=$2 _prompt=$3 _check=${4:-}
	eval "_val=\$$_var"
	if [ -z "$_val" ] && [ "$INTERACTIVE" = 1 ]; then
		prompt_line "$_prompt" ''
		_val=$REPLY
	fi
	while [ -n "$_val" ] && [ -n "$_check" ] && ! "$_check" "$_val"; do
		[ "$INTERACTIVE" = 1 ] || die "invalid $_flag: $_val"
		prompt_line "$_prompt" ''
		_val=$REPLY
	done
	eval "$_var=\$_val"
}

ask_list() { # VAR FLAG PROMPT VALIDATOR REQUIRED(yes|no); answers split on spaces
	_var=$1 _flag=$2 _prompt=$3 _check=$4 _req=$5
	eval "_val=\$$_var"
	while :; do
		if [ -z "$_val" ] && [ "$INTERACTIVE" = 1 ]; then
			prompt_line "$_prompt" ''
			_val=$(printf '%s\n' "$REPLY" | tr '\t' ' ' | tr -s ' ' '\n' | sed '/^$/d')
		fi
		if [ -z "$_val" ] && [ "$_req" = yes ]; then
			[ "$INTERACTIVE" = 1 ] || die "missing value: $_flag"
			continue
		fi
		_bad=0
		IFS=$NL
		for _i in $_val; do "$_check" "$_i" || _bad=1; done
		IFS=$OIFS
		[ "$_bad" = 0 ] && break
		[ "$INTERACTIVE" = 1 ] || die "invalid $_flag"
		_val=''
	done
	eval "$_var=\$_val"
}

choose() { # VAR FLAG PROMPT DEFAULT VALUE DESCRIPTION [VALUE DESCRIPTION]...
	_var=$1 _flag=$2 _prompt=$3 _def=$4
	shift 4
	eval "_val=\$$_var"
	_vals='' _menu='' _n=0 _defn=''
	while [ $# -ge 2 ]; do
		_n=$((_n + 1))
		_vals=$_vals$1$NL
		_menu=$_menu$(printf '  %d) %-11s %s' "$_n" "$1" "$2")$NL
		[ "$1" = "$_def" ] && _defn=$_n
		shift 2
	done
	while :; do
		if [ -n "$_val" ]; then
			case $NL$_vals in *"$NL$_val$NL"*) break ;; esac
			[ "$INTERACTIVE" = 1 ] || die "invalid $_flag: $_val (one of: $(printf '%s' "$_vals" | tr '\n' ' '))"
			printf '  not one of the choices: %s\n' "$_val" >&2
		elif [ "$INTERACTIVE" = 0 ]; then
			[ -n "$_def" ] || die "missing value: $_flag"
			_val=$_def
			continue
		fi
		printf '%s\n%s' "$_prompt" "$_menu" >&2
		prompt_line '  choice' "$_defn"
		_val=${REPLY:-$_defn}
		case $_val in
		[1-9] | [1-9][0-9]) [ "$_val" -le "$_n" ] && _val=$(printf '%s' "$_vals" | sed -n "${_val}p") ;;
		esac
	done
	eval "$_var=\$_val"
}

ask_yn() { # VAR PROMPT DEFAULT(yes|no)
	_var=$1 _prompt=$2 _def=$3
	eval "_val=\$$_var"
	if [ -z "$_val" ] && [ "$INTERACTIVE" = 1 ]; then
		while :; do
			if [ "$_def" = yes ]; then prompt_line "$_prompt [Y/n]" ''; else prompt_line "$_prompt [y/N]" ''; fi
			case $REPLY in
			'') _val=$_def ;;
			[Yy] | [Yy][Ee][Ss]) _val=yes ;;
			[Nn] | [Nn][Oo]) _val=no ;;
			*) continue ;;
			esac
			break
		done
	fi
	eval "$_var=\${_val:-\$_def}"
}

# With NEEDS, an auth flag: --yes stops, as dropping it would leave the node open.
drop() { # VAR FLAG [NEEDS]
	eval "_val=\$$1"
	[ -z "$_val" ] || [ -z "${3:-}" ] || [ "$INTERACTIVE" = 1 ] || die "$2 needs $3"
	[ -z "$_val" ] || warn "$2 does not apply to these choices; ignored"
	eval "$1=''"
}

# --- validators: print why and fail; free text rejects control characters, which
# would break out of a TOML string ---

bad() { printf '  %s\n' "$*" >&2; return 1; }
v_port() {
	case $1 in '' | *[!0-9]* | 0* | ??????*) ;; *) [ "$1" -le 65535 ] && return 0 ;; esac
	bad "not a port (1-65535): $1"
}
v_abs() {
	case $1 in *:* | *[[:cntrl:]]*) bad "':' (a mount separator) or a control character in a path: $1" ;; /*) return 0 ;; *) bad "not an absolute path: $1" ;; esac
}
v_ident() { case $1 in '' | *[!A-Za-z0-9._@-]*) bad "use letters, digits and . _ @ -: $1" ;; esac; }
v_cname() { case $1 in [A-Za-z0-9]*) case $1 in *[!A-Za-z0-9_.-]*) ;; *) return 0 ;; esac ;; esac; bad "not a container name: $1"; }
v_host() { case $1 in '' | *[!A-Za-z0-9.:%_-]*) bad "not a host name or address: $1" ;; esac; }
v_glob() { case $1 in */* | *[[:cntrl:]]* | '') bad "a file name pattern, without '/' or control characters: $1" ;; esac; }
v_word() { case $1 in '' | *[!A-Za-z0-9_./:@-]*) bad "unexpected characters: $1" ;; esac; }
v_any() { case $1 in '' | *[[:cntrl:]]*) bad "an empty value or a control character: $1" ;; esac; }
v_file() {
	[ -f "$1" ] && [ -r "$1" ] && return 0
	[ "$DRY_RUN" = 1 ] && { warn "not a readable file here: $1"; return 0; }
	bad "not a readable file: $1"
}
v_dir() { # a directory the service reads or writes
	v_abs "$1" || return 1
	[ "$RUNTIME/$TARGET_OS" = native/linux ] || return 0
	case $1/ in /tmp/* | /var/tmp/*) bad "the systemd unit gives lw its own /tmp and /var/tmp (PrivateTmp=yes): $1" ;; esac
}
v_logdir() {
	v_dir "$1" || return 1
	[ -d "$ROOT$1" ] && return 0
	[ "$DRY_RUN" = 1 ] && { warn "no such directory here: $ROOT$1"; return 0; }
	bad "no such directory: $ROOT$1"
}

# --- arguments ---

need_arg() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
	case $1 in
	--*=*)
		_o=${1%%=*} _v=${1#*=}
		shift
		set -- "$_o" "$_v" "$@"
		;;
	esac
	case $1 in
	-h | --help) usage; exit 0 ;;
	-y | --yes) YES=1 ;;
	-n | --dry-run) DRY_RUN=1 ;;
	--force) FORCE=yes ;;
	--start) START=yes ;;
	--no-start) START=no ;;
	--tls) TLS=yes ;;
	--no-tls) TLS=no ;;
	--build) BUILD=yes ;;
	--no-build) BUILD=no ;;
	--log-dir) need_arg "$@"; LOG_DIRS=$(add_item "$LOG_DIRS" "$2"); shift ;;
	--allow) need_arg "$@"; ALLOW=$(add_item "$ALLOW" "$2"); shift ;;
	--add-user) need_arg "$@"; ADD_USERS=$(add_item "$ADD_USERS" "$2"); shift ;;
	--sink-allow) need_arg "$@"; SINK_ALLOW=$(add_item "$SINK_ALLOW" "$2"); shift ;;
	--add-viewer) need_arg "$@"; ADD_VIEWERS=$(add_item "$ADD_VIEWERS" "$2"); shift ;;
	--*)
		case $1 in
		--role) _var=ROLE ;; --runtime) _var=RUNTIME ;; --engine) _var=ENGINE ;;
		--os) _var=TARGET_OS ;; --name) _var=NAME ;; --config-dir) _var=CONF_DIR ;;
		--jail) _var=JAIL ;; --log-pattern) _var=LOG_PATTERN ;; --from) _var=FROM ;;
		--log-group) _var=LOG_GROUP ;; --chain) _var=CHAIN ;; --aggregator) _var=AGGREGATOR ;;
		--chain-port) _var=CHAIN_PORT ;; --node) _var=NODE ;; --listen) _var=LISTEN ;;
		--file-dir) _var=FILE_DIR ;; --file-name) _var=FILE_NAME ;; --http-port) _var=HTTP_PORT ;;
		--tcp-port) _var=TCP_PORT ;; --format) _var=FORMAT ;; --cert-file) _var=CERT_FILE ;;
		--key-file) _var=KEY_FILE ;; --ca-file) _var=CA_FILE ;; --server-name) _var=SERVER_NAME ;;
		--auth) _var=AUTH ;; --username) _var=USERNAME ;; --password-file) _var=PASSWORD_FILE ;;
		--sink-auth) _var=SINK_AUTH ;; --secrets-dir) _var=SECRETS_DIR ;; --image) _var=IMAGE ;;
		--build-ca) _var=BUILD_CA ;; --build-flags) _var=BUILD_FLAGS ;; --network) _var=NETWORK ;;
		--bin) _var=BIN ;; --package-dir) _var=PACKAGE_DIR ;;
		*) die "unknown option: $1 (see $PROG -h)" ;;
		esac
		need_arg "$@"
		[ -n "$2" ] || die "$1 needs a value"
		eval "$_var=\$2"
		shift
		;;
	*) die "unexpected argument: $1 (see $PROG -h)" ;;
	esac
	shift
done

if [ "$YES" = 1 ]; then
	INTERACTIVE=0
elif [ -t 0 ]; then
	INTERACTIVE=1
elif [ "$DRY_RUN" = 1 ]; then
	INTERACTIVE=0
else
	die "stdin is not a terminal: pass --yes and the values as flags"
fi

# --- questions ---

host_os() {
	case $(uname -s) in
	Linux) echo linux ;;
	FreeBSD) echo freebsd ;;
	*) echo unknown ;;
	esac
}

short_host() { _h=$(uname -n); printf '%s' "${_h%%.*}"; }

freebsd_no_containers() {
	cat >&2 <<'EOF'
FreeBSD has no Docker. Podman on FreeBSD runs FreeBSD OCI images only, and the
LogWisp image is a Linux image, so containers are not supported there. Run
LogWisp natively instead: on the host, or inside a jail with --jail NAME.
EOF
}

jail_guide() {
	cat >&2 <<EOF
Jail "$JAIL" is not running here. Create and start it first, for example in
/etc/jail.conf.d/$JAIL.conf:
  $JAIL {
    path = "/usr/local/jails/$JAIL";
    host.hostname = "$JAIL";
    ip4.addr = "lo1|10.0.0.10/32";    # or an address on a real interface
    exec.start = "/bin/sh /etc/rc";
    exec.stop = "/bin/sh /etc/rc.shutdown";
    mount.devfs;
  }
then extract a base system (base.txz) into its path and start it:
  sysrc jail_enable=YES && service jail start $JAIL
A one-off jail without a file: jail -c name=$JAIL path=... host.hostname=$JAIL \\
  ip4.addr=... exec.start="/bin/sh /etc/rc" persist
EOF
}

resolve() {
	choose ROLE --role "Role of this node:" edge \
		edge "tail log files, forward them to an aggregator" \
		aggregator "receive from edges; write files, serve streams" \
		standalone "tail log files; write files, serve streams"

	HOST_OS=$(host_os)
	[ -n "$TARGET_OS" ] || TARGET_OS=$HOST_OS
	case $TARGET_OS in linux | freebsd) ;; *) die "unsupported target OS: $TARGET_OS (--os linux|freebsd)" ;; esac
	_dv=docker
	[ "$TARGET_OS" = freebsd ] && _dv=native
	[ "$RUNTIME" = podman ] && RUNTIME=docker ENGINE=${ENGINE:-podman}
	choose RUNTIME --runtime "Run it as:" "$_dv" \
		docker "docker container (Linux)" \
		podman "podman container (Linux)" \
		native "service: systemd on Linux, rc.d on FreeBSD or in a jail" \
		manual "write the configuration only; run lw yourself"
	[ "$RUNTIME" = podman ] && RUNTIME=docker ENGINE=podman
	if [ "$RUNTIME" = docker ] && [ "$TARGET_OS" = freebsd ]; then
		freebsd_no_containers
		[ "$INTERACTIVE" = 1 ] || die "use --runtime native (add --jail NAME for a jail)"
		_sw=''
		ask_yn _sw "Install natively instead?" yes
		[ "$_sw" = yes ] || exit 1
		RUNTIME=native
	fi
	if [ "$RUNTIME" = native ] && [ "$TARGET_OS" != "$HOST_OS" ] && [ "$DRY_RUN" = 0 ]; then
		die "--os $TARGET_OS with --runtime native needs a $TARGET_OS host (or --dry-run, or --runtime manual)"
	fi
	if [ "$RUNTIME/$TARGET_OS" = native/linux ] && [ -f "$PKG_UNIT" ] && { [ -n "$BIN" ] || [ "$BUILD" = yes ]; }; then
		die "a package provides lw ($PKG_UNIT); drop --bin/--build"
	fi
	[ -n "$ENGINE" ] || ENGINE=docker
	case $ENGINE in docker | podman) ;; *) die "invalid --engine: $ENGINE (docker|podman)" ;; esac
	[ "$RUNTIME" = native ] && [ -n "$CONF_DIR" ] && die "a native install keeps its configuration in SYSCONFDIR/logwisp; --config-dir is for containers and manual"
	if [ -n "$JAIL" ] && [ "$RUNTIME/$TARGET_OS" != native/freebsd ]; then
		die "--jail needs --runtime native on FreeBSD"
	fi

	ROOT=''
	case $RUNTIME in
	docker)
		ask NAME --name "Container name" "logwisp-$ROLE" v_cname
		ask CONF_DIR --config-dir "Host directory for the configuration (mounted at /etc/logwisp)" "/etc/logwisp/$NAME" v_abs
		CONF_HOST=$CONF_DIR CONF_LW=/etc/logwisp
		ask IMAGE --image "Image" logwisp:dev v_word
		;;
	native)
		if [ "$TARGET_OS" = freebsd ]; then
			ask_opt JAIL --jail "Jail to install into (empty: this host)" v_cname
			if [ -n "$JAIL" ]; then
				ROOT=$(jls -j "$JAIL" path 2>/dev/null) || ROOT=''
				if [ -z "$ROOT" ]; then
					jail_guide
					[ "$DRY_RUN" = 1 ] || exit 1
					ROOT=/usr/local/jails/$JAIL
					warn "showing paths under $ROOT"
				fi
			fi
			CONF_LW=/usr/local/etc/logwisp
		else
			CONF_LW=/etc/logwisp
		fi
		CONF_HOST=$ROOT$CONF_LW
		;;
	manual)
		ask CONF_DIR --config-dir "Directory for the configuration" "$HOME_DIR/logwisp-$ROLE" v_abs
		CONF_HOST=$CONF_DIR CONF_LW=$CONF_DIR
		;;
	esac

	if [ "$ROLE" != aggregator ]; then
		if [ -z "$LOG_DIRS" ] && [ "$INTERACTIVE" = 1 ]; then
			note "Log directories to tail, one per line; an empty line ends the list." >&2
			while :; do
				prompt_line "  directory" ''
				[ -n "$REPLY" ] || { [ -n "$LOG_DIRS" ] && break; continue; }
				v_logdir "$REPLY" && LOG_DIRS=$(add_item "$LOG_DIRS" "$REPLY")
			done
		fi
		ask_list LOG_DIRS --log-dir "Log directories, space-separated" v_logdir yes
		ask LOG_PATTERN --log-pattern "File name pattern in each directory" '*.log' v_glob
		FROM=${FROM:-end}
		case $FROM in start | end) ;; *) die "invalid --from: $FROM (start|end)" ;; esac
		[ "$RUNTIME" = manual ] || ask_opt LOG_GROUP --log-group "Group that may read these logs, for the service (empty: none)" v_ident
	fi

	if [ "$ROLE" != standalone ]; then
		choose CHAIN --chain "Chain transport:" tcp \
			tcp "tcp_chain: one long-lived connection" \
			http "http_chain: batched HTTP POSTs"
		_dv=9440
		[ "$CHAIN" = http ] && _dv=9441
		if [ "$ROLE" = edge ]; then
			ask AGGREGATOR --aggregator "Aggregator host or address" '' v_host
			ask CHAIN_PORT --chain-port "Aggregator chain port" "$_dv" v_port
			_dv=$(short_host)
			[ -z "$JAIL" ] || _dv=$JAIL
			ask NODE --node "Node label for this edge's entries" "$_dv" v_ident
		else
			ask CHAIN_PORT --chain-port "Chain listener port" "$_dv" v_port
		fi
	fi

	if [ "$ROLE" != edge ]; then
		ask LISTEN --listen "Listen address" 0.0.0.0 v_host
		if [ -z "$FILE_DIR$HTTP_PORT$TCP_PORT" ]; then
			[ "$INTERACTIVE" = 1 ] || die "no output: give --file-dir, --http-port or --tcp-port"
			_want='' _dv=/var/log/logwisp
			[ "$RUNTIME" = docker ] && _dv=/var/log/$NAME
			[ "$RUNTIME" = manual ] && _dv=$CONF_DIR/out
			ask_yn _want "Write the entries to rotating files?" yes
			[ "$_want" = no ] || ask FILE_DIR --file-dir "Output directory" "$_dv" v_dir
			_want=''
			ask_yn _want "Serve a live HTTP stream (SSE) with a status endpoint?" no
			[ "$_want" = no ] || ask HTTP_PORT --http-port "HTTP port" 8080 v_port
			_want=''
			ask_yn _want "Serve a plain TCP stream?" no
			[ "$_want" = no ] || ask TCP_PORT --tcp-port "TCP port" 9090 v_port
			[ -n "$FILE_DIR$HTTP_PORT$TCP_PORT" ] || die "no output chosen"
		fi
		[ -z "$FILE_DIR" ] || ask FILE_DIR --file-dir "Output directory" '' v_dir
		[ -z "$FILE_DIR" ] || ask FILE_NAME --file-name "Output file name stem" logwisp v_ident
		[ -z "$HTTP_PORT" ] || ask HTTP_PORT --http-port "HTTP port" '' v_port
		[ -z "$TCP_PORT" ] || ask TCP_PORT --tcp-port "TCP port" '' v_port
		choose FORMAT --format "Entry format:" txt \
			txt "timestamp, level, node/source, message" \
			json "one JSON object per entry" \
			raw "the message only"
		_dup=$(printf '%s\n' "$CHAIN_PORT" "$HTTP_PORT" "$TCP_PORT" | sed '/^$/d' | sort | uniq -d)
		[ -z "$_dup" ] || die "two listeners on port $_dup"
	fi

	# A standalone node without network outputs has no link to secure.
	if [ "$ROLE" = standalone ] && [ -z "$HTTP_PORT$TCP_PORT" ]; then
		[ "$TLS" != yes ] || warn "ignoring --tls: no http or tcp output"
		TLS=no
	fi
	_dv=no
	[ -z "$CERT_FILE$CA_FILE" ] || _dv=yes
	ask_yn TLS "Use TLS on this node's network links?" "$_dv"
	# Auth-only flags imply their mode, the default --yes takes.
	_ia=none _isa=none
	[ -z "$ALLOW" ] || _ia=mtls
	[ -z "$ADD_USERS$USERNAME$PASSWORD_FILE" ] || _ia=scram
	[ -z "$SINK_ALLOW" ] || _isa=mtls
	[ -z "$ADD_VIEWERS" ] || _isa=scram
	if [ "$TLS" = yes ]; then
		[ "$INTERACTIVE" = 0 ] || note "Certificates come from openssl or your PKI: doc/security.md#enabling-mtls" >&2
		if [ "$ROLE" = edge ]; then
			ask_opt CA_FILE --ca-file "CA bundle verifying the aggregator (empty: the system roots)" v_file
		else
			ask CERT_FILE --cert-file "This node's certificate (PEM)" '' v_file
			ask KEY_FILE --key-file "Its private key (PEM)" '' v_file
		fi
		[ "$ROLE" = standalone ] || choose AUTH --auth "Authenticate the chain link:" "$_ia" \
			none "TLS only" \
			mtls "client certificates, admitted by CN" \
			scram "username and password"
	else
		[ -z "$CERT_FILE$KEY_FILE$CA_FILE$SERVER_NAME" ] || die "certificate options need --tls"
		[ -z "$AUTH" ] || [ "$AUTH" = none ] || die "--auth $AUTH needs --tls"
		[ -z "$SINK_AUTH" ] || [ "$SINK_AUTH" = none ] || die "--sink-auth $SINK_AUTH needs --tls"
	fi
	[ "$ROLE" != standalone ] || drop AUTH --auth
	AUTH=${AUTH:-none}

	case $ROLE/$AUTH in
	edge/mtls)
		ask CERT_FILE --cert-file "This edge's client certificate (PEM)" '' v_file
		ask KEY_FILE --key-file "Its private key (PEM)" '' v_file
		ask_list ALLOW --allow "Aggregator certificate CN to pin (empty: any the CA issued)" v_any no
		;;
	edge/scram)
		ask PASSWORD_FILE --password-file "Password file (from the aggregator's secrets directory)" '' v_file
		# The aggregator names each generated password file after its user.
		_dv=${PASSWORD_FILE##*/}
		_dv=${_dv%.pass}
		case $_dv in '' | *[!A-Za-z0-9._@-]*) _dv=$NODE ;; esac
		ask USERNAME --username "SCRAM username" "$_dv" v_ident
		;;
	aggregator/mtls)
		ask CA_FILE --ca-file "CA bundle verifying the edges' certificates" '' v_file
		ask_list ALLOW --allow "Edge certificate CNs to admit, space-separated (empty: any the CA issued)" v_any no
		;;
	aggregator/scram)
		_req=yes
		[ -s "$CONF_HOST/users.toml" ] && _req=no
		ask_list ADD_USERS --add-user "Edge usernames to create or update, space-separated" v_ident "$_req"
		;;
	esac
	_c=${CERT_FILE:+1} _k=${KEY_FILE:+1}
	[ "$_c" = "$_k" ] || die "--cert-file and --key-file go together"

	_viewers=no
	[ "$ROLE" != edge ] && [ -n "$HTTP_PORT$TCP_PORT" ] && [ "$TLS" = yes ] && _viewers=yes
	if [ "$_viewers" = yes ]; then
		choose SINK_AUTH --sink-auth "Authenticate the stream viewers (http/tcp outputs):" "$_isa" \
			none "TLS only" \
			mtls "client certificates, admitted by CN" \
			scram "username and password (lw auth token / stream)"
		case $SINK_AUTH in
		mtls)
			ask CA_FILE --ca-file "CA bundle verifying the viewers' certificates" '' v_file
			ask_list SINK_ALLOW --sink-allow "Viewer certificate CNs to admit (empty: any the CA issued)" v_any no
			;;
		scram)
			_req=yes
			[ -s "$CONF_HOST/viewers.toml" ] && _req=no
			ask_list ADD_VIEWERS --add-viewer "Viewer usernames to create or update, space-separated" v_ident "$_req"
			;;
		esac
	else
		SINK_AUTH=none
	fi

	# Values the choices made moot are dropped, so the plan shows what applies.
	_n='--auth scram (TLS, on an edge)'
	[ "$ROLE/$AUTH" = edge/mtls ] || [ "$ROLE/$AUTH" = aggregator/mtls ] ||
		drop ALLOW --allow '--auth mtls (TLS, on an edge or aggregator)'
	[ "$ROLE/$AUTH" = edge/scram ] || { drop USERNAME --username "$_n"; drop PASSWORD_FILE --password-file "$_n"; }
	[ "$ROLE/$AUTH" = aggregator/scram ] || drop ADD_USERS --add-user '--auth scram (TLS, on an aggregator)'
	[ "$SINK_AUTH" = mtls ] || drop SINK_ALLOW --sink-allow '--sink-auth mtls (TLS, an http or tcp output)'
	[ "$SINK_AUTH" = scram ] || drop ADD_VIEWERS --add-viewer '--sink-auth scram (TLS, an http or tcp output)'
	[ "$ROLE" = edge ] || { drop SERVER_NAME --server-name; drop AGGREGATOR --aggregator; drop NODE --node; }
	[ "$ROLE" != edge ] || { drop FILE_DIR --file-dir; drop HTTP_PORT --http-port; drop TCP_PORT --tcp-port; }
	[ "$ROLE" != aggregator ] || drop LOG_DIRS --log-dir
	[ -z "$SERVER_NAME" ] || v_host "$SERVER_NAME" || exit 1
	if [ -n "$ADD_USERS$ADD_VIEWERS" ]; then
		ask SECRETS_DIR --secrets-dir "Directory for the generated passwords" "$HOME_DIR/logwisp-secrets" v_abs
	else
		drop SECRETS_DIR --secrets-dir
	fi

	if [ "$RUNTIME" = docker ]; then
		if [ -z "$BUILD" ]; then
			if "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; then
				BUILD=no
			elif [ "$INTERACTIVE" = 1 ]; then
				ask_yn BUILD "Image $IMAGE is not here; build it from $REPO?" yes
			else
				BUILD=no
				warn "image $IMAGE is not here; $ENGINE will try to pull it (--build builds it)"
			fi
		fi
		[ -z "$BUILD_CA" ] || v_file "$BUILD_CA" || exit 1
		[ -z "$NETWORK" ] || v_word "$NETWORK" || exit 1
		if [ "$NETWORK" != host ] && [ "$ROLE" != edge ]; then
			case $LISTEN in *:*) ;; *[!0-9.]*) die "--listen $LISTEN: a container publishes its ports on an IP address, not a host name" ;; esac
		fi
	fi
	[ -z "$BIN" ] || v_file "$BIN" || exit 1
	for _var in CERT_FILE KEY_FILE CA_FILE PASSWORD_FILE BUILD_CA BIN; do
		eval "_val=\$$_var"
		case $_val in '' | /*) ;; *) eval "$_var=\$PWD/\$_val" ;; esac
	done
	BUILD=${BUILD:-no}
	[ "$RUNTIME" = manual ] && START=no
	ask_yn START "Start it now?" yes
}

# --- derived values ---

derive() {
	C_CERT=$CONF_LW/tls/node.crt C_KEY=$CONF_LW/tls/node.key C_CA=$CONF_LW/tls/ca.crt
	C_PASS=$CONF_LW/chain.pass C_USERS=$CONF_LW/users.toml C_VIEWERS=$CONF_LW/viewers.toml
	CONF_T=${CONF_HOST#"$ROOT"} # CONF_HOST as seen from inside the target
	LISTEN=${LISTEN:-0.0.0.0}
	BIND=$LISTEN
	[ "$RUNTIME" = docker ] && [ "$NETWORK" != host ] && BIND=0.0.0.0
	FILE_MODE=0640 SECRET_MODE=0600
	[ "$RUNTIME" = native ] && SECRET_MODE=0640
	CHOWN_IMAGE=0 USERNS=''
	if [ "$RUNTIME" = docker ]; then
		if [ "$(id -u)" = 0 ]; then
			CHOWN_IMAGE=1
		elif [ "$ENGINE" = podman ]; then
			USERNS=keep-id:uid=65532,gid=65532
		elif [ "$DRY_RUN" = 0 ]; then
			die "run as root: the configuration must belong to the image user $IMAGE_USER"
		fi
	fi
	LOG_GID=''
	if [ "$RUNTIME" = docker ] && [ -n "$LOG_GROUP" ]; then
		LOG_GID=$(getent group "$LOG_GROUP" 2>/dev/null | cut -d: -f3)
		[ -n "$LOG_GID" ] || die "no such group here: $LOG_GROUP"
	fi
	case $RUNTIME in
	docker) DESC="$ENGINE container $NAME" ;;
	native) DESC="systemd service logwisp" ;;
	manual) DESC="configuration for lw -c" ;;
	esac
	[ "$RUNTIME/$TARGET_OS" = native/freebsd ] && DESC="rc.d service logwisp${JAIL:+ in jail $JAIL}"
	OLD_CONF='' OLD_CTR=''
	[ ! -f "$CONF_HOST/logwisp.toml" ] || OLD_CONF=$CONF_HOST/logwisp.toml
	if [ "$RUNTIME/$START" = docker/yes ] && "$ENGINE" container inspect "$NAME" >/dev/null 2>&1; then
		OLD_CTR=$NAME
	fi
}

# --- the configuration ---

tls_listener() { # PREFIX AUTH
	[ "$TLS" = yes ] || return 0
	printf '[%s.tls]\nenabled = true\ncert_file = %s\nkey_file = %s\n' "$1" "$(tq "$C_CERT")" "$(tq "$C_KEY")"
	[ "$2" != mtls ] || printf 'client_auth = true\nclient_ca_file = %s\n' "$(tq "$C_CA")"
}

auth_listener() { # PREFIX AUTH ALLOW CREDENTIALS
	case $2 in
	mtls) printf '[%s.auth]\ntype = "mtls"\nallow = %s\n' "$1" "$(tlist "$3")" ;;
	scram) printf '[%s.auth]\ntype = "scram"\ncredentials_file = %s\n' "$1" "$(tq "$4")" ;;
	esac
}

gen_config() {
	printf '# LogWisp %s node (%s), written by deploy/lw-deploy.sh.\n#\n' "$ROLE" "$DESC"
	not_covered '# '
	printf '\n[logging]\noutput = "stdout"\nlevel = "info"\n\n[[pipelines]]\nname = "%s"\n' "$ROLE"
	[ "$ROLE" = edge ] || printf '\n[pipelines.flow.format]\ntype = "%s"\n' "$FORMAT"

	_n=0
	IFS=$NL
	for _d in $LOG_DIRS; do
		IFS=$OIFS
		_n=$((_n + 1))
		_id=logs
		[ "$_n" = 1 ] || _id=logs_$_n
		printf '\n[[pipelines.plugin_sources]]\nid = "%s"\ntype = "file"\n[pipelines.plugin_sources.config]\n' "$_id"
		printf 'directory = %s\npattern = %s\nfrom = "%s"\n' "$(tq "$_d")" "$(tq "$LOG_PATTERN")" "$FROM"
	done
	IFS=$OIFS

	_p=pipelines.plugin_sources.config
	if [ "$ROLE" = aggregator ]; then
		printf '\n[[pipelines.plugin_sources]]\nid = "from_edges"\ntype = "%s_chain"\n[%s]\n' "$CHAIN" "$_p"
		printf 'host = %s\nport = %s\n' "$(tq "$BIND")" "$CHAIN_PORT"
		tls_listener "$_p" "$AUTH"
		auth_listener "$_p" "$AUTH" "$ALLOW" "$C_USERS"
	fi

	_p=pipelines.plugin_sinks.config
	if [ "$ROLE" = edge ]; then
		printf '\n[[pipelines.plugin_sinks]]\nid = "to_aggregator"\ntype = "%s_chain"\n[%s]\n' "$CHAIN" "$_p"
		printf 'host = %s\nport = %s\nnode = %s\n' "$(tq "$AGGREGATOR")" "$CHAIN_PORT" "$(tq "$NODE")"
		if [ "$TLS" = yes ]; then
			printf '[%s.tls]\nenabled = true\n' "$_p"
			[ -z "$CA_FILE" ] || printf 'ca_file = %s\n' "$(tq "$C_CA")"
			[ -z "$SERVER_NAME" ] || printf 'server_name = %s\n' "$(tq "$SERVER_NAME")"
			[ -z "$CERT_FILE" ] || printf 'cert_file = %s\nkey_file = %s\n' "$(tq "$C_CERT")" "$(tq "$C_KEY")"
		fi
		case $AUTH in
		mtls) printf '[%s.auth]\ntype = "mtls"\nallow = %s\n' "$_p" "$(tlist "$ALLOW")" ;;
		scram) printf '[%s.auth]\ntype = "scram"\nusername = %s\npassword_file = %s\n' "$_p" "$(tq "$USERNAME")" "$(tq "$C_PASS")" ;;
		esac
		return 0
	fi
	if [ -n "$FILE_DIR" ]; then
		printf '\n[[pipelines.plugin_sinks]]\nid = "files"\ntype = "file"\n[%s]\n' "$_p"
		printf 'directory = %s\nname = %s\n' "$(tq "$FILE_DIR")" "$(tq "$FILE_NAME")"
	fi
	for _t in http tcp; do
		_port=$HTTP_PORT
		[ "$_t" = tcp ] && _port=$TCP_PORT
		[ -n "$_port" ] || continue
		printf '\n[[pipelines.plugin_sinks]]\nid = "%s"\ntype = "%s"\n[%s]\n' "$_t" "$_t" "$_p"
		printf 'host = %s\nport = %s\n' "$(tq "$BIND")" "$_port"
		tls_listener "$_p" "$SINK_AUTH"
		auth_listener "$_p" "$SINK_AUTH" "$SINK_ALLOW" "$C_VIEWERS"
	done
}

# --- the plan, and the command that repeats it ---

EQ=''
eq() {
	EQ="$EQ \\$NL    $1"
	[ $# -lt 2 ] || EQ="$EQ $(shquote "$2")"
}
eq_opt() { [ -z "$2" ] || eq "$1" "$2"; }
eq_list() {
	IFS=$NL
	for _e in $2; do eq "$1" "$_e"; done
	IFS=$OIFS
}

equivalent() {
	eq --role "$ROLE"
	if [ "$RUNTIME" = docker ] && [ "$ENGINE" = podman ]; then eq --runtime podman; else eq --runtime "$RUNTIME"; fi
	[ "$TARGET_OS" = "$HOST_OS" ] || eq --os "$TARGET_OS"
	eq_opt --jail "$JAIL"
	if [ "$RUNTIME" = docker ]; then
		eq --name "$NAME"
		eq --image "$IMAGE"
		[ "$BUILD" = no ] || eq --build
		eq_opt --build-ca "$BUILD_CA"
		eq_opt --build-flags "$BUILD_FLAGS"
		eq_opt --network "$NETWORK"
	fi
	[ "$RUNTIME" = native ] || eq --config-dir "$CONF_DIR"
	[ "$RUNTIME" != native ] || [ "$BUILD" = no ] || eq --build
	eq_opt --bin "$BIN"
	eq_list --log-dir "$LOG_DIRS"
	if [ "$ROLE" != aggregator ]; then
		eq --log-pattern "$LOG_PATTERN"
		eq --from "$FROM"
	fi
	eq_opt --log-group "$LOG_GROUP"
	if [ "$ROLE" != standalone ]; then
		eq --chain "$CHAIN"
		eq_opt --aggregator "$AGGREGATOR"
		eq --chain-port "$CHAIN_PORT"
		eq_opt --node "$NODE"
	fi
	if [ "$ROLE" != edge ]; then
		eq --listen "$LISTEN"
		eq_opt --file-dir "$FILE_DIR"
		[ -z "$FILE_DIR" ] || eq --file-name "$FILE_NAME"
		eq_opt --http-port "$HTTP_PORT"
		eq_opt --tcp-port "$TCP_PORT"
		eq --format "$FORMAT"
	fi
	if [ "$TLS" = yes ]; then eq --tls; else eq --no-tls; fi
	eq_opt --cert-file "$CERT_FILE"
	eq_opt --key-file "$KEY_FILE"
	eq_opt --ca-file "$CA_FILE"
	eq_opt --server-name "$SERVER_NAME"
	[ "$ROLE" = standalone ] || eq --auth "$AUTH"
	eq_list --allow "$ALLOW"
	eq_opt --username "$USERNAME"
	eq_opt --password-file "$PASSWORD_FILE"
	eq_list --add-user "$ADD_USERS"
	[ "$ROLE" = edge ] || [ "$TLS" = no ] || [ -z "$HTTP_PORT$TCP_PORT" ] || eq --sink-auth "$SINK_AUTH"
	eq_list --sink-allow "$SINK_ALLOW"
	eq_list --add-viewer "$ADD_VIEWERS"
	eq_opt --secrets-dir "$SECRETS_DIR"
	[ "$RUNTIME" = manual ] || { if [ "$START" = yes ]; then eq --start; else eq --no-start; fi; }
	printf '%s%s \\\n    --yes\n' "$(shquote "$0")" "$EQ"
}

plan() {
	note "LogWisp $ROLE node: $DESC"
	note "  configuration  $CONF_HOST/logwisp.toml"
	[ "$CONF_HOST" = "$CONF_LW" ] || note "                 (lw reads it as $CONF_LW/logwisp.toml)"
	[ -z "$OLD_CONF" ] || note "                 replacing the existing one, kept as logwisp.toml.bak"
	[ -z "$OLD_CTR" ] || note "  replaces       the existing container $OLD_CTR"
	IFS=$NL
	for _d in $LOG_DIRS; do note "  tails          $_d/$LOG_PATTERN"; done
	IFS=$OIFS
	_sec=plain
	[ "$TLS" = yes ] && _sec="TLS, auth $AUTH"
	[ "$ROLE" = edge ] && note "  forwards to    $(urlhost "$AGGREGATOR"):$CHAIN_PORT over ${CHAIN}_chain ($_sec) as node $NODE"
	[ "$ROLE" = aggregator ] && note "  receives on    $(urlhost "$LISTEN"):$CHAIN_PORT over ${CHAIN}_chain ($_sec)"
	_sec=plain
	[ "$TLS" = yes ] && _sec="TLS, auth $SINK_AUTH"
	[ -z "$FILE_DIR" ] || note "  writes         $FILE_DIR/$FILE_NAME.log ($FORMAT)"
	[ -z "$HTTP_PORT" ] || note "  serves http    $(urlhost "$LISTEN"):$HTTP_PORT /stream /status ($FORMAT, $_sec)"
	[ -z "$TCP_PORT" ] || note "  serves tcp     $(urlhost "$LISTEN"):$TCP_PORT ($FORMAT, $_sec)"
	[ -z "$ADD_USERS$ADD_VIEWERS" ] || note "  passwords      $SECRETS_DIR/USER.pass"
	note ""
	note "The same deployment without prompts:"
	equivalent
	note ""
	not_covered '  '
	note ""
}

# --- files ---

OWNED=''
own() { OWNED=$(add_item "$OWNED" "$1"); }

install_copy() { # SRC REL MODE: a copy inside the configuration directory
	own "$2"
	[ "$1" = "$CONF_HOST/$2" ] || put_file "$CONF_T/$2" "$3" "$1"
}

apply_owner() {
	_base=$CONF_T
	set --
	IFS=$NL
	for _r in $OWNED; do set -- "$@" "$_base/$_r"; done
	IFS=$OIFS
	case $RUNTIME in
	docker) [ "$CHOWN_IMAGE" = 0 ] || run chown "$IMAGE_USER" "$_base" "$@" || die "chown failed" ;;
	native) trun chown root:logwisp "$_base" "$@" || die "chown failed" ;;
	esac
}

output_dir() {
	[ -n "$FILE_DIR" ] || return 0
	case $RUNTIME in
	docker) _owner=$IMAGE_USER ;;
	native) _owner=logwisp:logwisp ;;
	*) _owner='' ;;
	esac
	if [ -d "$ROOT$FILE_DIR" ]; then
		# An existing directory keeps its owner: it may be shared.
		case $RUNTIME in
		docker) [ "$CHOWN_IMAGE" = 0 ] || [ -n "$(find "$FILE_DIR" -prune -user "${IMAGE_USER%:*}")" ] ||
			warn "$FILE_DIR must be writable by $IMAGE_USER: chown $IMAGE_USER $FILE_DIR" ;;
		native) [ "$DRY_RUN" = 1 ] || [ -n "$(tprobe find "$FILE_DIR" -prune -user logwisp)" ] ||
			warn "$FILE_DIR must be writable by logwisp: chown logwisp:logwisp $FILE_DIR" ;;
		esac
		return 0
	fi
	trun install -d -m 0750 "$FILE_DIR" || die "cannot create $FILE_DIR"
	case $RUNTIME in
	docker) [ "$CHOWN_IMAGE" = 0 ] || run chown "$_owner" "$FILE_DIR" ;;
	native) trun chown "$_owner" "$FILE_DIR" ;;
	esac
}

write_files() {
	if [ -d "$CONF_HOST" ] && [ ! -f "$CONF_HOST/logwisp.toml" ] && [ -n "$(ls -A "$CONF_HOST" 2>/dev/null)" ] && [ "$RUNTIME" != native ]; then
		die "$CONF_HOST holds other files; choose an empty or a LogWisp --config-dir"
	fi
	trun install -d -m 0750 "$CONF_T" || die "cannot create $CONF_HOST"
	if [ -n "$CERT_FILE$CA_FILE" ]; then
		own tls
		trun install -d -m 0750 "$CONF_T/tls" || die "cannot create $CONF_HOST/tls"
	fi
	[ -z "$CERT_FILE" ] || install_copy "$CERT_FILE" tls/node.crt "$FILE_MODE"
	[ -z "$KEY_FILE" ] || install_copy "$KEY_FILE" tls/node.key "$SECRET_MODE"
	[ -z "$CA_FILE" ] || install_copy "$CA_FILE" tls/ca.crt "$FILE_MODE"
	[ -z "$PASSWORD_FILE" ] || install_copy "$PASSWORD_FILE" chain.pass "$SECRET_MODE"
	_creds=''
	[ "$ROLE/$AUTH" != aggregator/scram ] || _creds=users.toml
	[ "$SINK_AUTH" != scram ] || _creds="$_creds viewers.toml"
	for _f in $_creds; do
		own "$_f"
		# lw auth keeps an existing file's owner and mode.
		[ -f "$CONF_HOST/$_f" ] || put_file "$CONF_T/$_f" "$SECRET_MODE" </dev/null
	done
	if [ -f "$CONF_HOST/logwisp.toml" ] && [ "$DRY_RUN" = 0 ]; then
		trun cp -p "$CONF_T/logwisp.toml" "$CONF_T/logwisp.toml.bak" || die "cannot keep a backup"
	fi
	own logwisp.toml
	_text=$(gen_config)
	put_file "$CONF_T/logwisp.toml" "$FILE_MODE" <<EOF
$_text
EOF
	apply_owner
	output_dir
}

gen_password() { # FILE: kept when it exists, so a rerun keeps the password
	[ -s "$1" ] && return 0
	printf '+ generate a password into %s\n' "$(shquote "$1")"
	[ "$DRY_RUN" = 1 ] && return 0
	(umask 077 && od -An -tx1 -N16 /dev/urandom | tr -d ' \n' >"$1" && echo >>"$1") || die "cannot write $1"
}

keep_passwords() { # CREDENTIALS(rel) NAMES: a new password would lock out an existing user
	IFS=$NL
	for _u in $2; do
		[ -s "$SECRETS_DIR/$_u.pass" ] || ! grep -qxF "username = \"$_u\"" "$CONF_HOST/$1" 2>/dev/null ||
			die "user $_u exists in $1, but $SECRETS_DIR/$_u.pass does not: give the --secrets-dir holding it, or remove the user (lw auth remove-user)"
	done
	IFS=$OIFS
}

add_users() { # CREDENTIALS(rel) NAMES
	[ -n "$2" ] || return 0
	_cred=$1
	IFS=$NL
	for _u in $2; do
		IFS=$OIFS
		_pw=$SECRETS_DIR/$_u.pass
		gen_password "$_pw"
		case $RUNTIME in
		docker)
			set -- "$ENGINE" run --rm -i --network none --read-only --cap-drop ALL \
				--security-opt no-new-privileges -u "$IMAGE_USER"
			[ -z "$USERNS" ] || set -- "$@" --userns "$USERNS"
			set -- "$@" -v "$CONF_HOST:/etc/logwisp" "$IMAGE"
			;;
		native)
			set -- "$BINDIR/lw"
			[ -z "$JAIL" ] || set -- jexec "$JAIL" "$@"
			;;
		manual) set -- "$LW" ;;
		esac
		run_in "$_pw" "$@" auth add-user -credentials "$CONF_LW/$_cred" -user "$_u" -password-file /dev/stdin ||
			die "adding user $_u failed"
	done
	IFS=$OIFS
}

# --- runtimes ---

pkg_text() { # FILE SED-SCRIPT
	if [ -f "$PACKAGE_DIR/$1" ]; then
		sed "$2" "$PACKAGE_DIR/$1"
	elif [ "$DRY_RUN" = 1 ]; then
		warn "missing $PACKAGE_DIR/$1"
		printf '(%s/%s, with %s applied)\n' "$PACKAGE_DIR" "$1" "$2"
	else
		die "missing $PACKAGE_DIR/$1 (--package-dir names another copy)"
	fi
}

pick_bin() { # CANDIDATE-DIRS: sets BINDIR, and BIN_SRC when lw must be installed
	BIN_SRC=$BIN BINDIR=/usr/local/bin
	[ -z "$BIN_SRC" ] || return 0
	for _d in $1; do
		[ -x "$ROOT$_d/lw" ] && { BINDIR=$_d; return 0; }
	done
	BIN_SRC=$REPO/bin/lw
	[ -x "$BIN_SRC" ] || [ "$DRY_RUN" = 1 ] || die "no lw binary: build it (make build, or --build) or pass --bin FILE"
}

linux_prepare() {
	command -v systemctl >/dev/null 2>&1 || [ "$DRY_RUN" = 1 ] || die "a native Linux install needs systemd; use --runtime docker or manual"
	if [ -f "$PKG_UNIT" ]; then
		# lw auth and lw --check run the binary the packaged unit starts.
		BINDIR=$(sed -n 's|^ExecStart=\(/[^ ]*\)/lw\( .*\)\{0,1\}$|\1|p' "$PKG_UNIT")
		[ -n "$BINDIR" ] || die "no lw in the ExecStart of $PKG_UNIT"
		note "using the packaged logwisp.service and $BINDIR/lw"
	else
		pick_bin '/usr/local/bin /usr/bin'
		[ -z "$BIN_SRC" ] || run install -m 0755 "$BIN_SRC" "$BINDIR/lw" || die "cannot install lw"
		_unit=$(pkg_text logwisp.service "s|@BINDIR@|$BINDIR|g; s|@SYSCONFDIR@|/etc|g") || exit 1
		put_file /etc/systemd/system/logwisp.service 0644 <<EOF
$_unit
EOF
		run install -d -m 0755 /etc/sysusers.d /etc/tmpfiles.d || exit 1
		for _f in sysusers tmpfiles; do
			_text=$(pkg_text "logwisp.$_f" '') || exit 1
			put_file "/etc/$_f.d/logwisp.conf" 0644 <<EOF
$_text
EOF
		done
		run systemd-sysusers /etc/sysusers.d/logwisp.conf || die "cannot create the logwisp user"
		run systemd-tmpfiles --create /etc/tmpfiles.d/logwisp.conf || die "cannot create the logwisp directories"
	fi

	_dropin=''
	case $FILE_DIR in '' | /var/log/logwisp | /var/lib/logwisp) ;; *) _dropin="${_dropin}ReadWritePaths=\"$FILE_DIR\"$NL" ;; esac
	case $NL$LOG_DIRS$NL$FILE_DIR in *"$NL/home"* | *"$NL/root"* | *"$NL/run/user"*) _dropin="${_dropin}ProtectHome=read-only$NL" ;; esac
	[ -z "$LOG_GROUP" ] || _dropin="${_dropin}SupplementaryGroups=$LOG_GROUP$NL"
	for _p in $CHAIN_PORT $HTTP_PORT $TCP_PORT; do
		[ "$ROLE" = edge ] && break
		if [ "$_p" -lt 1024 ]; then
			_dropin="${_dropin}CapabilityBoundingSet=CAP_NET_BIND_SERVICE${NL}AmbientCapabilities=CAP_NET_BIND_SERVICE$NL"
			break
		fi
	done
	_d=/etc/systemd/system/logwisp.service.d
	if [ -n "$_dropin" ]; then
		run install -d -m 0755 "$_d" || exit 1
		put_file "$_d/deploy.conf" 0644 <<EOF
# Written by deploy/lw-deploy.sh: this node's paths, groups and ports.
[Service]
$_dropin
EOF
	elif [ -f "$_d/deploy.conf" ]; then
		run rm -f "$_d/deploy.conf"
	fi
}

freebsd_prepare() {
	pick_bin /usr/local/bin
	trun install -d -m 0755 "$BINDIR" /usr/local/etc/rc.d || exit 1
	[ -z "$BIN_SRC" ] || put_file "$BINDIR/lw" 0755 "$BIN_SRC"
	if [ "$DRY_RUN" = 1 ] || ! tprobe pw usershow logwisp >/dev/null 2>&1; then
		trun pw useradd logwisp -d /nonexistent -s /usr/sbin/nologin -c "LogWisp log transport" ||
			die "cannot create the logwisp user"
	fi
	[ -z "$LOG_GROUP" ] || trun pw groupmod "$LOG_GROUP" -m logwisp || die "cannot add logwisp to $LOG_GROUP"
	_rc=$(pkg_text logwisp.rc "s|%%BINDIR%%|$BINDIR|g; s|%%PREFIX%%|/usr/local|g") || exit 1
	put_file /usr/local/etc/rc.d/logwisp 0555 <<EOF
$_rc
EOF
}

build_image() {
	set -- "$ENGINE" build
	[ -z "$BUILD_CA" ] || set -- "$@" --secret "id=build_ca,src=$BUILD_CA"
	for _v in HTTPS_PROXY HTTP_PROXY NO_PROXY https_proxy http_proxy no_proxy; do
		eval "_set=\${$_v+x}"
		[ -z "$_set" ] || set -- "$@" --build-arg "$_v"
	done
	IFS=' '
	# shellcheck disable=SC2086 # the flags are split on spaces by design
	set -- "$@" $BUILD_FLAGS
	IFS=$OIFS
	_ver=$(git -C "$REPO" describe --tags --always 2>/dev/null) || _ver=dev
	_rev=$(git -C "$REPO" rev-parse HEAD 2>/dev/null) || _rev=unknown
	run "$@" --build-arg "VERSION=$_ver" --build-arg "REVISION=$_rev" -t "$IMAGE" "$REPO" ||
		die "the image build failed (behind a proxy: --build-ca FILE, --build-flags \"--network host\")"
}

# --check builds every plugin as a start would, reading its TLS and credentials files.
conf_check() { # COMMAND...: lw, or the container that runs it
	run "$@" --check -c "$CONF_LW/logwisp.toml" ||
		die "lw --check rejects $CONF_HOST/logwisp.toml${OLD_CONF:+ (the previous one is logwisp.toml.bak)}"
}

docker_start() {
	set -- --read-only --cap-drop ALL --security-opt no-new-privileges -u "$IMAGE_USER"
	[ -z "$USERNS" ] || set -- "$@" --userns "$USERNS"
	[ -z "$LOG_GID" ] || set -- "$@" --group-add "$LOG_GID"
	set -- "$@" -v "$CONF_HOST:/etc/logwisp:ro"
	IFS=$NL
	for _d in $LOG_DIRS; do set -- "$@" -v "$_d:$_d:ro"; done
	IFS=$OIFS
	[ -z "$FILE_DIR" ] || set -- "$@" -v "$FILE_DIR:$FILE_DIR"
	conf_check "$ENGINE" run --rm --network none "$@" "$IMAGE"
	_net=''
	case $NETWORK in
	'' | host | bridge | none) ;;
	*) "$ENGINE" network inspect "$NETWORK" >/dev/null 2>&1 || _net=$NETWORK ;;
	esac
	if [ "$START" = yes ]; then
		[ -z "$_net" ] || run "$ENGINE" network create "$_net" || die "cannot create network $_net"
		[ -z "$OLD_CTR" ] || run "$ENGINE" rm -f "$NAME" || die "cannot remove container $NAME"
	fi
	[ -z "$NETWORK" ] || set -- "$@" --network "$NETWORK"
	if [ "$NETWORK" != host ] && [ "$ROLE" != edge ]; then
		for _p in $CHAIN_PORT $HTTP_PORT $TCP_PORT; do
			set -- "$@" -p "$(urlhost "$LISTEN"):$_p:$_p"
		done
	fi
	set -- "$ENGINE" run -d --name "$NAME" --restart unless-stopped "$@" "$IMAGE" -c /etc/logwisp/logwisp.toml
	if [ "$START" = no ]; then
		note "Start it with:"
		[ -z "$_net" ] || note "+ $ENGINE network create $_net"
		show_cmd "$@"
		printf '\n'
		return 0
	fi
	run "$@" || die "the container did not start"
	[ "$DRY_RUN" = 1 ] && return 0
	sleep 3
	_state=$("$ENGINE" inspect -f '{{.State.Running}} {{.RestartCount}}' "$NAME" 2>/dev/null)
	"$ENGINE" logs --tail 15 "$NAME" 2>&1 | sed 's/^/  | /'
	[ "$_state" = "true 0" ] || die "container $NAME is not running cleanly; see: $ENGINE logs $NAME"
	note "container $NAME is running"
}

native_start() {
	if [ "$TARGET_OS" = freebsd ]; then
		if [ "$START" = no ]; then
			note "Start it with: ${JAIL:+jexec $JAIL }sysrc logwisp_enable=YES && ${JAIL:+jexec $JAIL }service logwisp start"
			return 0
		fi
		trun sysrc logwisp_enable=YES || die "sysrc failed"
		trun service logwisp restart || die "the service did not start; see /var/log/messages"
		[ "$DRY_RUN" = 1 ] || { sleep 2; tprobe service logwisp status || die "the service is not running; see /var/log/messages"; }
		return 0
	fi
	run systemctl daemon-reload || exit 1
	if [ "$START" = no ]; then
		note "Start it with: systemctl enable --now logwisp"
		return 0
	fi
	run systemctl enable logwisp || exit 1
	run systemctl restart logwisp || die "the service did not start: journalctl -u logwisp"
	[ "$DRY_RUN" = 1 ] && return 0
	sleep 2
	systemctl is-active --quiet logwisp || { journalctl -u logwisp -n 20 --no-pager; die "the service is not running"; }
	note "service logwisp is running"
}

next_steps() {
	note ""
	note "Next:"
	case $RUNTIME in
	docker)
		note "  logs:    $ENGINE logs -f $NAME"
		note "  reload:  edit $CONF_HOST/logwisp.toml, then $ENGINE kill -s HUP $NAME"
		;;
	native)
		if [ "$TARGET_OS" = freebsd ]; then note "  logs:    /var/log/messages${JAIL:+ in jail $JAIL} (tag logwisp)"; else note "  logs:    journalctl -u logwisp -f"; fi
		if [ "$TARGET_OS" = freebsd ]; then _r="${JAIL:+jexec $JAIL }service logwisp reload"; else _r="systemctl reload logwisp"; fi
		note "  reload:  edit $CONF_LW/logwisp.toml, then $_r"
		;;
	manual) note "  run:     ${LW:-lw} -c $CONF_LW/logwisp.toml" ;;
	esac
	if [ -n "$HTTP_PORT" ]; then
		_h=$LISTEN
		[ "$_h" = 0.0.0.0 ] && _h=127.0.0.1
		[ "$_h" = :: ] && _h=::1
		if [ "$TLS" = yes ]; then _u=https; else _u=http; fi
		_u=$_u://$(urihost "$_h"):$HTTP_PORT
		case $SINK_AUTH in
		none)
			_c=''
			[ "$TLS" = no ] || _c='--cacert CA '
			note "  status:  curl $_c$_u/status"
			;;
		mtls) note "  status:  curl --cacert CA --cert CERT --key KEY $_u/status" ;;
		scram) note "  status:  curl with a bearer token from: lw auth token -url $_u -user USER -password-file FILE -ca-file CA (doc/cli.md)" ;;
		esac
		note "  stream:  $_u/stream"
	fi
	if [ -n "$ADD_USERS" ]; then
		note "  edges:   copy $SECRETS_DIR/USER.pass to each edge over a safe channel, then run"
		note "           there: $PROG --role edge --tls --auth scram --username USER --password-file FILE ..."
	fi
	[ -z "$ADD_VIEWERS" ] || note "  viewers: lw auth token / lw auth stream with $SECRETS_DIR/USER.pass (doc/cli.md)"
	if [ "$ROLE" != standalone ] && [ "$AUTH" = none ]; then
		note "  without chain auth the aggregator admits any peer and trusts the node label it claims"
	fi
	if [ "$SINK_AUTH" = none ] && [ -n "$HTTP_PORT$TCP_PORT" ]; then
		note "  the http/tcp outputs admit anyone who reaches them: bind --listen to a trusted address"
	fi
}

main() {
	resolve
	derive
	plan
	if [ "$DRY_RUN" = 1 ]; then
		note "Dry run: nothing below is changed."
		note ""
	elif [ "$INTERACTIVE" = 1 ]; then
		_go=''
		ask_yn _go "Apply?" yes
		[ "$_go" = yes ] || exit 0
	elif [ -n "$OLD_CONF$OLD_CTR" ] && [ "$FORCE" != yes ]; then
		die "${OLD_CONF:-container $NAME} exists (--force replaces it)"
	fi

	keep_passwords users.toml "$ADD_USERS"
	keep_passwords viewers.toml "$ADD_VIEWERS"
	case $RUNTIME in
	docker)
		[ "$DRY_RUN" = 1 ] || "$ENGINE" info >/dev/null 2>&1 || die "cannot reach $ENGINE"
		[ "$BUILD" = no ] || build_image
		;;
	native)
		[ "$DRY_RUN" = 1 ] || [ "$(id -u)" = 0 ] || die "a native install needs root"
		if [ "$BUILD" = yes ]; then
			run make -C "$REPO" build || die "make build failed"
			BIN=$REPO/bin/lw
		fi
		if [ "$TARGET_OS" = freebsd ]; then freebsd_prepare; else linux_prepare; fi
		;;
	manual)
		LW=$BIN
		[ -n "$LW" ] || LW=$(command -v lw 2>/dev/null) || LW=''
		[ -n "$LW" ] || LW=$REPO/bin/lw
		[ -z "$ADD_USERS$ADD_VIEWERS" ] || [ -x "$LW" ] || [ "$DRY_RUN" = 1 ] || die "no lw binary to add users with: --bin FILE"
		;;
	esac

	write_files
	[ -z "$ADD_USERS$ADD_VIEWERS" ] || run install -d -m 0700 "$SECRETS_DIR" || die "cannot create $SECRETS_DIR"
	add_users users.toml "$ADD_USERS"
	add_users viewers.toml "$ADD_VIEWERS"

	case $RUNTIME in
	docker) docker_start ;;
	native)
		if [ -n "$JAIL" ]; then conf_check jexec "$JAIL" "$BINDIR/lw"; else conf_check "$BINDIR/lw"; fi
		native_start
		;;
	manual) [ ! -x "$LW" ] || conf_check "$LW" ;;
	esac
	next_steps
}

main

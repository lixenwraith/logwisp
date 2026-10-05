# Skeleton for sysutils/logwisp: GO_MODULE fetches the tagged module from the
# Go proxy, so it waits for a release tag, a maintainer and a UIDs/GIDs entry
# for logwisp (doc/todo.md). files/logwisp.in is a symlink to
# deploy/package/logwisp.rc: copy the port with cp -RL.

PORTNAME=	logwisp
DISTVERSIONPREFIX=	v
DISTVERSION=	0.21.0
CATEGORIES=	sysutils

MAINTAINER=	maintainer@example.org
COMMENT=	Pipeline-based log transport with TLS and SCRAM authentication
WWW=		https://github.com/lixenwraith/logwisp

LICENSE=	BSD3CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		go:1.27,modules
USE_RC_SUBR=	logwisp
SUB_LIST=	BINDIR=${PREFIX}/bin

GO_MODULE=	github.com/lixenwraith/logwisp
GO_TARGET=	./cmd/lw
GO_BUILDFLAGS=	-ldflags="-s -w \
		-X github.com/lixenwraith/logwisp/internal/version.Version=${DISTVERSION} \
		-X github.com/lixenwraith/logwisp/internal/version.GitCommit=${DISTVERSIONFULL}"

USERS=		logwisp
GROUPS=		logwisp

OPTIONS_DEFINE=	DOCS
PORTDOCS=	*

post-install:
	${INSTALL_MAN} ${WRKSRC}/doc/lw.1 ${STAGEDIR}${PREFIX}/share/man/man1
	${MKDIR} ${STAGEDIR}${PREFIX}/share/bash-completion/completions \
		${STAGEDIR}${PREFIX}/share/fish/vendor_completions.d \
		${STAGEDIR}${PREFIX}/share/zsh/site-functions
	${INSTALL_DATA} ${WRKSRC}/deploy/package/completion/lw.bash \
		${STAGEDIR}${PREFIX}/share/bash-completion/completions/lw
	${INSTALL_DATA} ${WRKSRC}/deploy/package/completion/lw.fish \
		${STAGEDIR}${PREFIX}/share/fish/vendor_completions.d
	${INSTALL_DATA} ${WRKSRC}/deploy/package/completion/_lw \
		${STAGEDIR}${PREFIX}/share/zsh/site-functions
	${MKDIR} ${STAGEDIR}${ETCDIR}
	${INSTALL_DATA} ${WRKSRC}/config/logwisp.toml ${STAGEDIR}${ETCDIR}/logwisp.toml.sample

post-install-DOCS-on:
	${MKDIR} ${STAGEDIR}${DOCSDIR}/doc
	${INSTALL_DATA} ${WRKSRC}/README.md ${STAGEDIR}${DOCSDIR}
	${INSTALL_DATA} ${WRKSRC}/doc/*.md ${STAGEDIR}${DOCSDIR}/doc

.include <bsd.port.mk>

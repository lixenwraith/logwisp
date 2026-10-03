# Skeleton for sysutils/logwisp. GO_MODULE fetches the module by its canonical
# path, so it waits for the module rename to github.com/lixenwraith/logwisp
# (the -X paths below follow it), a tagged release, a maintainer, and a
# UIDs/GIDs entry for logwisp. files/logwisp.in links to ../logwisp.rc: cp -L.

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
		-X logwisp/internal/version.Version=${DISTVERSION} \
		-X logwisp/internal/version.GitCommit=${DISTVERSIONFULL}"

USERS=		logwisp
GROUPS=		logwisp

OPTIONS_DEFINE=	DOCS
PORTDOCS=	*

post-install:
	${INSTALL_MAN} ${WRKSRC}/doc/lw.1 ${STAGEDIR}${PREFIX}/share/man/man1
	${MKDIR} ${STAGEDIR}${ETCDIR}
	${INSTALL_DATA} ${WRKSRC}/config/logwisp.toml ${STAGEDIR}${ETCDIR}/logwisp.toml.sample

post-install-DOCS-on:
	${MKDIR} ${STAGEDIR}${DOCSDIR}/doc
	${INSTALL_DATA} ${WRKSRC}/README.md ${STAGEDIR}${DOCSDIR}
	${INSTALL_DATA} ${WRKSRC}/doc/*.md ${STAGEDIR}${DOCSDIR}/doc

.include <bsd.port.mk>

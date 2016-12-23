-include Config.mk

################ Source files ##########################################

EXE	:= $O${NAME}
SRCS	:= $(wildcard *.c)
OBJS	:= $(addprefix $O,$(SRCS:.c=.o))
DEPS	:= ${OBJS:.o=.d}
CONFS	:= Config.mk config.h
ONAME   := $(notdir $(abspath $O))

################ Compilation ###########################################

.PHONY: all clean distclean maintainer-clean

all:	Config.mk config.h ${EXE}

${EXE}:	${OBJS}
	@echo "Linking $@ ..."
	@${LD} ${LDFLAGS} -o $@ $^ ${LIBS}

$O%.o:	%.c
	@echo "    Compiling $< ..."
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@${CC} ${CFLAGS} -MMD -MT "$(<:.c=.s) $@" -o $@ -c $<

%.s:	%.c
	@echo "    Compiling $< to assembly ..."
	@${CC} ${CFLAGS} -S -o $@ -c $<

################ Installation ##########################################

.PHONY:	install uninstall

ifdef BINDIR
EXEI	:= ${BINDIR}/$(notdir ${EXE})
PAMCNFI	:= ${PAMDIR}/${EXE}
SYSDCFI	:= ${SYSDDIR}/${EXE}@.service
MANI	:= ${MANDIR}/man1/${EXE}.1.gz

install:	${EXEI} ${PAMCNFI} ${SYSDCFI} ${MANI}

${EXEI}:	${EXE}
	@echo "Installing $< as $@ ..."
	@${INSTALLEXE} $< $@

${PAMCNFI}:	conf/${EXE}
	@echo "Installing PAM configuration file ..."
	@${INSTALLDATA} $< $@

${SYSDCFI}:	conf/${EXE}@.service
	@echo "Installing systemd service file ..."
	@${INSTALLDATA} $< $@

${MANI}:	conf/${EXE}.1
	@echo "Installing man page ..."
	@gzip -9 -c $< > $@
	@chmod 644 $@

uninstall:
	@echo "Uninstalling ${EXE} ..."
	@rm -f ${EXEI} ${PAMCNFI} ${SYSDCFI} ${MANI}
endif

################ Maintenance ###########################################

clean:
	@if [ -h ${ONAME} ]; then\
	    rm -f ${EXE} ${OBJS} ${DEPS} $O.d ${ONAME};\
	    ${RMPATH} ${BUILDDIR};\
	fi

distclean:	clean
	@rm -f ${CONFS} config.status

maintainer-clean: distclean

$O.d:   ${BUILDDIR}/.d
	@[ -h ${ONAME} ] || ln -sf ${BUILDDIR} ${ONAME}
${BUILDDIR}/.d:     Makefile
	@mkdir -p ${BUILDDIR} && touch ${BUILDDIR}/.d

Config.mk:	Config.mk.in
config.h:	config.h.in
${OBJS}:	Makefile ${CONFS} $O.d
${CONFS}:	configure
	@if [ -x config.status ]; then\
	    echo "Reconfiguring ..."; ./config.status;\
	else\
	    echo "Running configure ..."; ./configure;\
	fi

-include ${DEPS}

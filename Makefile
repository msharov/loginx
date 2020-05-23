-include Config.mk

################ Source files ##########################################

exe	:= $O${name}
srcs	:= $(wildcard *.c)
objs	:= $(addprefix $O,$(srcs:.c=.o))
deps	:= ${objs:.o=.d}
confs	:= Config.mk config.h
oname   := $(notdir $(abspath $O))

################ Compilation ###########################################

.SUFFIXES:
.PHONY: all clean distclean maintainer-clean

all:	${exe}

${exe}:	${objs}
	@echo "Linking $@ ..."
	@${CC} ${ldflags} -o $@ $^ ${libs}

$O%.o:	%.c
	@echo "    Compiling $< ..."
	@${CC} ${cflags} -MMD -MT "$(<:.c=.s) $@" -o $@ -c $<

%.s:	%.c
	@echo "    Compiling $< to assembly ..."
	@${CC} ${cflags} -S -o $@ -c $<

################ Installation ##########################################

.PHONY:	install installdirs
.PHONY: uninstall uninstall-man uninstall-pam uninstall-svc

ifdef sbindir
exed	:= ${DESTDIR}${sbindir}
exei	:= ${exed}/$(notdir ${exe})

${exed}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${exei}:	${exe} | ${exed}
	@echo "Installing $@ ..."
	@${INSTALL_PROGRAM} $< $@

installdirs:	${exed}
install:	${exei}
uninstall:
	@if [ -f ${exei} ]; then\
	    echo "Removing ${exei} ...";\
	    rm -f ${exei};\
	fi
endif
ifdef man1dir
mand	:= ${DESTDIR}${man1dir}
mani	:= ${mand}/${name}.1

${mand}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${mani}:	conf/${name}.1 | ${mand}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

installdirs:	${mand}
install:	${mani}
uninstall:	uninstall-man
uninstall-man:
	@if [ -f ${mani} ]; then\
	    echo "Removing ${mani} ...";\
	    rm -f ${mani};\
	fi
endif
ifdef pamdir
pamd	:= ${DESTDIR}${pamdir}
pami	:= ${pamd}/${name}

${pamd}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${pami}:	conf/${name} | ${pamd}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

installdirs:	${pamd}
install:	${pami}
uninstall:	uninstall-pam
uninstall-pam:
	@if [ -f ${pami} ]; then\
	    echo "Removing ${pami} ...";\
	    rm -f ${pami};\
	fi
endif
ifdef sysddir
svcd	:= ${DESTDIR}${sysddir}
svci	:= ${svcd}/${name}@.service

${svcd}:
	@echo "Creating $@ ..."
	@${INSTALL} -d $@
${svci}:	conf/${name}@.service | ${svcd}
	@echo "Installing $@ ..."
	@${INSTALL_DATA} $< $@

installdirs:	${svcd}
install:	${svci}
uninstall:	uninstall-svc
uninstall-svc:
	@if [ -f ${svci} ]; then\
	    echo "Removing ${svci} ...";\
	    rm -f ${svci};\
	fi
endif

################ Maintenance ###########################################

clean:
	@if [ -d ${builddir} ]; then\
	    rm -f ${exe} ${objs} ${deps} $O.d;\
	    rmdir ${builddir};\
	fi

distclean:	clean
	@rm -f ${oname} ${confs} config.status

maintainer-clean: distclean

$O.d:	${builddir}/.d
	@[ -h ${oname} ] || ln -sf ${builddir} ${oname}
$O%/.d:	$O.d
	@[ -d $(dir $@) ] || mkdir $(dir $@)
	@touch $@
${builddir}/.d:	Makefile
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@touch $@

Config.mk:	Config.mk.in
config.h:	config.h.in
${objs}:	Makefile ${confs} $O.d
${confs}:	configure
	@if [ -x config.status ]; then echo "Reconfiguring ...";\
	    ./config.status;\
	else echo "Running configure ...";\
	    ./configure;\
	fi

-include ${dep}

#------------------------------------------------------------------------------
# File: Makefile
# 
# Note: This Makefile requires GNU make.
# 
# (c) 2001,2000 Stanford University
#
#------------------------------------------------------------------------------

all : sr

CC = gcc

OSTYPE = $(shell uname)

ifeq ($(OSTYPE),CYGWIN_NT-5.1)
ARCH = -D_CYGWIN_
endif

ifeq ($(OSTYPE),Linux)
ARCH = -D_LINUX_
SOCK = -lnsl -lresolv
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket -lresolv
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK = -lresolv
endif

# Include directories for headers
INCLUDES = -Icore -Iarp -Irouting -Iinterface -Iutils -Inetwork -Icrypto

CFLAGS = -g -Wall -D_DEBUG_ -D_GNU_SOURCE $(ARCH) $(INCLUDES)

LIBS= $(SOCK) -lm -lpthread
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER} 
PURIFY= purify ${PFLAGS}

# Core Router Files
CORE_SRCS = core/sr_router.c core/sr_main.c
CORE_HDRS = core/sr_router.h core/sr_protocol.h

# ARP Cache Management
ARP_SRCS = arp/sr_arpcache.c
ARP_HDRS = arp/sr_arpcache.h

# Routing Table
ROUTING_SRCS = routing/sr_rt.c
ROUTING_HDRS = routing/sr_rt.h

# Interface Management
INTERFACE_SRCS = interface/sr_if.c
INTERFACE_HDRS = interface/sr_if.h

# Utilities
UTILS_SRCS = utils/sr_utils.c utils/sr_dumper.c
UTILS_HDRS = utils/sr_utils.h utils/sr_dumper.h

# Network Communication
NETWORK_SRCS = network/sr_vns_comm.c
NETWORK_HDRS = network/vnscommand.h

# Cryptography
CRYPTO_SRCS = crypto/sha1.c
CRYPTO_HDRS = crypto/sha1.h

# All source files
sr_SRCS = $(CORE_SRCS) $(ARP_SRCS) $(ROUTING_SRCS) $(INTERFACE_SRCS) \
          $(UTILS_SRCS) $(NETWORK_SRCS) $(CRYPTO_SRCS)

# All header files
sr_HDRS = $(CORE_HDRS) $(ARP_HDRS) $(ROUTING_HDRS) $(INTERFACE_HDRS) \
          $(UTILS_HDRS) $(NETWORK_HDRS) $(CRYPTO_HDRS)

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS))
sr_DEPS = $(patsubst %.c,%.d,$(sr_SRCS))

# Build object files from source files in subdirectories
$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

# Generate dependency files in the same directory as source files
%.d : %.c
	@mkdir -p $(dir $@)
	$(CC) -MM $(CFLAGS) $< | sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' > $@

-include $(sr_DEPS)	

sr : $(sr_OBJS)
	$(CC) $(CFLAGS) -o sr $(sr_OBJS) $(LIBS) 

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)

.PHONY : clean clean-deps dist    

clean:
	rm -f core/*.o arp/*.o routing/*.o interface/*.o utils/*.o network/*.o crypto/*.o
	rm -f core/*.d arp/*.d routing/*.d interface/*.d utils/*.d network/*.d crypto/*.d
	rm -f .*.d  # Remove any old dependency files from root directory
	rm -f *~ sr *.dump *.tar tags

clean-deps:
	rm -f core/*.d arp/*.d routing/*.d interface/*.d utils/*.d network/*.d crypto/*.d
	rm -f .*.d  # Remove any old dependency files from root directory

tags:
	find core arp routing interface utils network crypto -name "*.c" -o -name "*.h" | xargs ctags



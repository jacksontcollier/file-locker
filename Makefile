DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
CC = gcc
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td
CFLAGS = -Wall -std=gnu11
LFLAGS = -lssl -lcrypto
SRCS = rsa-sign.c rsa-validate.c cbcmac-tag.c cbcmac-validate.c rsa-keygen.c lock.c unlock.c
TARGET_EXE = rsa-sign rsa-validate cbcmac-tag cbcmac-validate rsa-keygen lock unlock

.PHONY: all
all: $(TARGET_EXE)

.PHONY: clean
clean:
	rm *.o .d/* $(TARGET_EXE)

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) -c
POSTCCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

rsa-sign: rsa-sign.o
	$(CC) rsa-sign.o -o rsa-sign

rsa-validate: rsa-validate.o
	$(CC) rsa-validate.o -o rsa-validate

cbcmac-tag: cbcmac-tag.o
	$(CC) cbcmac-tag.o -o cbcmac-tag

cbcmac-validate: cbcmac-validate.o
	$(CC) cbcmac-validate.o -o cbcmac-validate

rsa-keygen: rsa-keygen.o padded-rsa.o
	$(CC) rsa-keygen.o padded-rsa.o $(LFLAGS) -o rsa-keygen

lock: lock.o
	$(CC) lock.o -o lock

unlock: unlock.o
	$(CC) unlock.o -o unlock

%.o : %.c
%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $<
	$(POSTCOMPILE)

$(DEPDIR)/%d: ;
.PRECIOUS: $(DEPDIR)/%.d

include $(wildcard $(patsubst %,$(DEPDIR)%.d,$(basename $(SRCS))))

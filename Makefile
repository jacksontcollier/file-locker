DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
CC = gcc
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td
CFLAGS = -Wall -std=gnu11 -g
LFLAGS = -lssl -lcrypto -pthread
SRCS = rsa-sign.c rsa-validate.c cbcmac-tag.c cbcmac-validate.c rsa-keygen.c \
       lock.c unlock.c file-locker.c
TARGET_EXE = $(BINDIR)/rsa-sign $(BINDIR)/rsa-validate $(BINDIR)/cbcmac-tag \
             $(BINDIR)/cbcmac-validate $(BINDIR)/rsa-keygen $(BINDIR)/lock \
	     $(BINDIR)/unlock
TARGET_LN = rsa-sign rsa-validate cbcmac-tag cbcmac-validate rsa-keygen lock unlock
SRCDIR = src
BINDIR = bin
OUTPUT_OPTS = -o $@

.PHONY: all
all: BUILDDIRS $(TARGET_EXE) $(TARGET_LN)

.PHONY: clean
clean:
	rm -rf $(BINDIR)/* .d/* $(TARGET_LN)

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) -c
POSTCCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

BUILDDIRS:
	$(shell mkdir -p bin)

rsa-sign: $(BINDIR)/rsa-sign
	$(shell ln -s $(BINDIR)/rsa-sign rsa-sign)

rsa-validate: $(BINDIR)/rsa-validate
	$(shell ln -s $(BINDIR)/rsa-validate rsa-validate)

cbcmac-tag: $(BINDIR)/cbcmac-tag
	$(shell ln -s $(BINDIR)/cbcmac-tag cbcmac-tag)

cbcmac-validate: $(BINDIR)/cbcmac-validate
	$(shell ln -s $(BINDIR)/cbcmac-validate cbcmac-validate)

rsa-keygen: $(BINDIR)/rsa-keygen
	$(shell ln -s $(BINDIR)/rsa-keygen rsa-keygen)

lock: $(BINDIR)/lock
	$(shell ln -s $(BINDIR)/lock lock)

unlock: $(BINDIR)/unlock
	$(shell ln -s $(BINDIR)/unlock unlock)

$(BINDIR)/rsa-sign: $(BINDIR)/rsa-sign.o $(BINDIR)/file-locker.o \
                    $(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o
	$(CC) $(BINDIR)/rsa-sign.o $(BINDIR)/file-locker.o \
	$(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o $(LFLAGS) \
	-o $(BINDIR)/rsa-sign

$(BINDIR)/rsa-validate: $(BINDIR)/rsa-validate.o $(BINDIR)/file-locker.o \
			$(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o
	$(CC) $(BINDIR)/rsa-validate.o $(BINDIR)/file-locker.o \
	$(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o $(LFLAGS) \
	-o $(BINDIR)/rsa-validate

$(BINDIR)/cbcmac-tag: $(BINDIR)/cbcmac-tag.o $(BINDIR)/file-locker.o \
		      $(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o
	$(CC) $(BINDIR)/cbcmac-tag.o $(BINDIR)/file-locker.o \
	$(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o $(LFLAGS) \
	-o $(BINDIR)/cbcmac-tag

$(BINDIR)/cbcmac-validate: $(BINDIR)/cbcmac-validate.o \
			   $(BINDIR)/file-locker.o $(BINDIR)/padded-rsa.o \
			   $(BINDIR)/aes-modes.o
	$(CC) $(BINDIR)/cbcmac-validate.o $(BINDIR)/file-locker.o \
	$(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o $(LFLAGS) -o \
	$(BINDIR)/cbcmac-validate

$(BINDIR)/rsa-keygen: $(BINDIR)/rsa-keygen.o $(BINDIR)/padded-rsa.o
	$(CC) $(BINDIR)/rsa-keygen.o $(BINDIR)/padded-rsa.o $(LFLAGS) -o $(BINDIR)/rsa-keygen

$(BINDIR)/lock: $(BINDIR)/lock.o $(BINDIR)/file-locker.o \
		$(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o
	$(CC) $(BINDIR)/lock.o $(BINDIR)/file-locker.o $(BINDIR)/padded-rsa.o \
	$(BINDIR)/aes-modes.o $(LFLAGS) -o $(BINDIR)/lock

$(BINDIR)/unlock: $(BINDIR)/unlock.o $(BINDIR)/file-locker.o \
		  $(BINDIR)/padded-rsa.o $(BINDIR)/aes-modes.o
	$(CC) $(BINDIR)/unlock.o $(BINDIR)/file-locker.o $(BINDIR)/padded-rsa.o \
	$(BINDIR)/aes-modes.o $(LFLAGS) -o $(BINDIR)/unlock

$(BINDIR)/%.o : $(SRCDIR)/%.c
$(BINDIR)/%.o : $(SRCDIR)/%.c $(DEPDIR)/%.d
	$(COMPILE.c) $< $(OUTPUT_OPTS)
	$(POSTCOMPILE)

$(DEPDIR)/%d: ;
.PRECIOUS: $(DEPDIR)/%.d

include $(wildcard $(patsubst %,$(DEPDIR)%.d,$(basename $(SRCS))))

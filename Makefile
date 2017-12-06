DEPDIR := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
CC = gcc
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td
CFLAGS = -Wall
SRCS = rsa-sign.c
TARGET_EXE = rsa-sign

.PHONY: all
all: $(TARGET_EXE)

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) -c
POSTCCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

rsa-sign: rsa-sign.o
	$(CC) rsa-sign.o -o rsa-sign

%.o : %.c
%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(DEPDIR)/%d: ;
.PRECIOUS: $(DEPDIR)/%.d

include $(wildcard $(patsubst %,$(DEPDIR)%.d,$(basename $(SRCS))))

EXENAME := exploit

CC ?= cc

CFLAGS += -Os -g3
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic

LDFLAGS += -static

all: $(EXENAME)

$(EXENAME): exploit.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	@rm -f $(EXENAME)

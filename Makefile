CC      = clang
CFLAGS  = -Wall -Wextra -Werror -O2 -pthread -I$(INCDIR)
SRCDIR  = src
INCDIR  = include
OBJDIR  = out/obj
BINDIR  = out/bin
TARGET  = $(BINDIR)/killchain
SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

TIDY_CHECKS = -checks=clang-analyzer-*,cert-*,bugprone-*,performance-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-bugprone-easily-swappable-parameters

.PHONY: all clean format lint check

all: $(TARGET)

$(TARGET): $(OBJS) | $(BINDIR)
	$(CC) -g $(OBJS) -o $(TARGET)
	objcopy --only-keep-debug $(TARGET) $(TARGET).debug
	objcopy --strip-debug --add-gnu-debuglink=$(TARGET).debug $(TARGET)
	sha256sum $(SRCS) > shasum.txt
	sha256sum $(TARGET) >> shasum.txt
	sha256sum Makefile >> shasum.txt

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -g -c $< -o $@

$(OBJDIR) $(BINDIR):
	mkdir -p $@

format:
	clang-format -i $(SRCS)

lint:
	clang-tidy $(TIDY_CHECKS) --warnings-as-errors='*' $(SRCS) -- -I$(INCDIR)

check: $(TARGET)
	sudo valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --extra-debuginfo-path=$(BINDIR) \$(TARGET) 8.8.8.8 - || true

clean:
	rm -rf $(OBJDIR) $(BINDIR) shasum.txt

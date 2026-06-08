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

.PHONY: all clean format lint sha256

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

clean:
	rm -rf $(OBJDIR) $(BINDIR) shasum.txt

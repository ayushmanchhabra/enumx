CC      = clang
CFLAGS  = -Wall -Wextra -Werror
TARGET  = killchain.exe
OBJ     = killchain.o
SRC     = killchain.c

TIDY_CHECKS = -checks=clang-analyzer-*,cert-*,bugprone-*,performance-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,-bugprone-easily-swappable-parameters

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)
	sha256sum ./$(SRC) > ./shasum.txt
	sha256sum ./$(TARGET) >> ./shasum.txt
	sha256sum ./Makefile >> ./shasum.txt

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

format:
	clang-format -i $(SRC)

lint:
	clang-tidy $(TIDY_CHECKS) --warnings-as-errors='*' $(SRC) --

clean:
	rm -f $(OBJ) $(TARGET)

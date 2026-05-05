CC      = clang
CFLAGS  = -Wall -Wextra -Werror
TARGET  = stealth.exe
OBJ     = stealth.o
SRC     = stealth.c

TIDY_CHECKS = -checks=clang-analyzer-*,cert-*,bugprone-*,performance-*

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

format:
	clang-format -i $(SRC)

tidy:
	clang-tidy $(TIDY_CHECKS) $(SRC) -- 

lint: format tidy

clean:
	rm -f $(OBJ) $(TARGET)

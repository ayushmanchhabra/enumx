CC      = clang
CFLAGS  = -Wall -Wextra -Werror
TARGET  = killchain.exe
OBJ     = killchain.o
SRC     = killchain.c

TIDY_CHECKS = -checks=clang-analyzer-*,cert-*,bugprone-*,performance-*

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)
	sha256sum ./$(SRC) > ./shasum.txt
	sha256sum ./$(TARGET) >> ./shasum.txt
	sha256sum ./Makefile >> ./shasum.txt

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

format:
	clang-format -i $(SRC)

tidy:
	clang-tidy $(TIDY_CHECKS) $(SRC) -- 

lint: format tidy

clean:
	rm -f $(OBJ) $(TARGET)

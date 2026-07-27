# Compiler and flags
CC = gcc
CFLAGS = -Os -s -municode -static

# Targets
TARGET = POP42Patcher.exe
SRC = POP42Patcher.c
OBJ = main.o

# Default target
all: $(TARGET)

# Compile
main.o: $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Link everything
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -municode -static -s -o $(TARGET)

# Clean
clean:
	rm -f $(OBJ) $(TARGET)
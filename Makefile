CC      = gcc
CCFLAGS = -g -Wall
BIN_DIR = bin
SRC_DIR = src

SNIFFER  = sniffer

all: $(SNIFFER)
$(SNIFFER): $(SRC_DIR)/$(SNIFFER).c $(BIN_DIR)
	$(CC) $(CCFLAGS) -o ./$(BIN_DIR)/$(SNIFFER) $(SRC_DIR)/$(SNIFFER).c

$(BIN_DIR):
	if [ ! -d ./bin ]; then mkdir ./bin; fi

clean:
	$(RM) ./$(BIN_DIR)/$(SNIFFER)

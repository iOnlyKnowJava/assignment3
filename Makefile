TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build
KATHARA_SHARED_DIR = $(TOP_DIR)/kathara-labs/shared
CC=gcc
FLAGS = -pthread -fPIC -g -ggdb -pedantic -Wall -Wextra -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/ut_packet.o $(BUILD_DIR)/ut_tcp.o $(BUILD_DIR)/backend.o

all: server client

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(FLAGS) -c -o $@ $<

server: $(OBJS) $(SRC_DIR)/server.c
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)
	cp server $(KATHARA_SHARED_DIR)

client: $(OBJS) $(SRC_DIR)/client.c
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS)
	cp client $(KATHARA_SHARED_DIR)

test:
	cd support/execs && SUBMISSION_DIR=../.. make all && cd ../..
	python3 run_tests.py

clean:
	rm -f $(BUILD_DIR)/*.o client server

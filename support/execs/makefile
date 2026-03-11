TOP_DIR := $(shell pwd)
SUBMISSION_DIR ?= "/autograder/submission"
INC_DIR = $(SUBMISSION_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(SUBMISSION_DIR)/build

CC=gcc
FLAGS = -DSUPPORT_PATH="\"$(TOP_DIR)/../\"" -pthread -fPIC -g -ggdb -Wall -I$(INC_DIR)
OBJS = $(BUILD_DIR)/* -lm

all:
	$(CC) $(FLAGS) $(SRC_DIR)/mitm.cpp -o $(TOP_DIR)/mitm -std=c++11 -lstdc++ -O3
	$(CC) $(FLAGS) $(SRC_DIR)/grader_client.c -o $(TOP_DIR)/grader_client $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/grader_killer.c -o $(TOP_DIR)/grader_killer $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/grader_reliable_client.c -o $(TOP_DIR)/grader_reliable_client $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/grader_reliable_server.c -o $(TOP_DIR)/grader_reliable_server $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/grader_sender.c -o $(TOP_DIR)/grader_sender $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/grader_server.c -o $(TOP_DIR)/grader_server $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/grader_wait.c -o $(TOP_DIR)/grader_wait $(OBJS)

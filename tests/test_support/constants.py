import os

PWD = os.path.dirname(os.path.realpath(__file__))
ASSN_PATH = os.getenv("ASSN_PATH", f"{PWD}/../..")
SUPPORT_FILE_PATH = f"{ASSN_PATH}/support/"

GRADER_REL_SERVER = SUPPORT_FILE_PATH + "execs/grader_reliable_server"
GRADER_REL_CLIENT = SUPPORT_FILE_PATH + "execs/grader_reliable_client"

GRADER_SERVER = SUPPORT_FILE_PATH + "execs/grader_server"
GRADER_CLIENT = SUPPORT_FILE_PATH + "execs/grader_client"
GRADER_SENDER = SUPPORT_FILE_PATH + "execs/grader_sender"
GRADER_WAITER = SUPPORT_FILE_PATH + "execs/grader_wait"
GRADER_KILLER = SUPPORT_FILE_PATH + "execs/grader_killer"

MITM = SUPPORT_FILE_PATH + "execs/mitm"
LOCALHOST = "127.0.0.1"
GRADER_PORTNO = 12000
BUFFER_SIZE = 4096

FREE_PORT_12000 = "printf 'yes' | freeport 12000"
FREE_PORT_15441 = "printf 'yes' | freeport 15441"

# global variables that we use across multiple functions

global fqdnregex
global ptrregex
global emailregex
fqdnregex = '^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$'
ptrregex = '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
emailregex = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

global INFO
global WARN
global LOW
global MAYBE
global MONEY
INFO = "\033[1m\033[36m[*]\033[0m "
WARN = "\033[1m\033[31m[!]\033[0m "
LOW = "\033[1m\033[34m[-]\033[0m "
MAYBE = "\033[1m\033[35m[?]\033[0m "
MONEY = "\033[1m\033[38m[$]\033[0m "
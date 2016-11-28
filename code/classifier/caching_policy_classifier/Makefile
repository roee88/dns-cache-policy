# Declaration of variables
CC = g++
CC_FLAGS = -w -std=c++1y -g
LDLIBS = -ltins -lpcap -lpthread -lboost_system
 
# File names
EXEC = app
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

# Main target
$(EXEC): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDLIBS) -o $(EXEC) -g
#	$(CC) $(OBJECTS) $(LDLIBS) -o $(EXEC)

# To obtain object files
%.o: %.cpp
	$(CC) -c $(CC_FLAGS) $< -o $@

# To remove generated files
clean:
	rm -f $(EXEC) $(OBJECTS)

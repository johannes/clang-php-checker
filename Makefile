LLVM_CONFIG ?= llvm-config
CXX ?= clang++

FLAGS = `$(LLVM_CONFIG) --cxxflags` $(CXXFLAGS)

PHPChecker.so: PHPZPPChecker.cpp
	$(CXX) $(FLAGS) -shared -o PHPChecker.so PHPZPPChecker.cpp

all: PHPChecker.so

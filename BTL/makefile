# ============================================================
#  Makefile – HMAC Project (Windows & Linux)
# ============================================================
#
#  WINDOWS (cmd):
#    mingw32-make          hoặc
#    g++ -std=c++17 -O2 main_demo.cpp Sha256.cpp basic_mac.cpp -o demo.exe
#    demo.exe
#
#  LINUX / MAC (terminal):
#    make
#    ./demo
# ============================================================

CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall

# Chỉ cần compile 2 file .cpp, các .h được include tự động
SRCS = main_demo.cpp Sha256.cpp basic_mac.cpp

# Tên output: demo.exe (Windows) hoặc demo (Linux)
ifeq ($(OS),Windows_NT)
    OUT = demo.exe
else
    OUT = demo
endif

all: $(OUT)

$(OUT): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(OUT)
	@echo "Bien dich xong! Chay: ./$(OUT)"

run: all
	./$(OUT)

clean:
	rm -f demo demo.exe
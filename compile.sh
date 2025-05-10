#!/bin/bash
# Compile script for luban_toolkit_tui.cpp
# Version: 3.0.0 - Static build with optimizations

# Default options
COMPILER="g++"
OPT_LEVEL="-O3" # Highest optimization level
WARNINGS="-Wall -Wextra" # Default warnings enabled
STD_FLAG="-std=c++17"
THREAD_FLAG="-pthread"
BUILD_DIR="build"
OUTPUT="$BUILD_DIR/luban_toolkit_tui"
INPUT="luban_toolkit_tui.cpp"
FTXUI_INCLUDE="-I./FTXUI/include"
FTXUI_LINK="-L./FTXUI/build -lftxui-component -lftxui-dom -lftxui-screen"

# Static linking flags - fully static build
STATIC_FLAGS="-static"
# Additional optimization flags
EXTRA_OPT="-march=native -flto -ffunction-sections -fdata-sections"
# Linker optimization
LINK_OPT="-Wl,--gc-sections"

# Flag to control warnings
ENABLE_WARNINGS=true

# Process command line arguments
for arg in "$@"
do
    case $arg in
        --no-warnings)
        ENABLE_WARNINGS=false
        shift # Remove --no-warnings from processing
        ;;
        *)
        # Unknown option, maybe handle later or ignore
        ;;
    esac
done

# Check if g++ is installed
if ! command -v $COMPILER &> /dev/null; then
    echo "Error: $COMPILER not found. Please install g++."
    exit 1
fi

# Check if input file exists
if [ ! -f "$INPUT" ]; then
    echo "Error: Input file $INPUT not found."
    exit 2
fi

# Check if FTXUI headers exist
if [ ! -d "./FTXUI/include" ]; then
    echo "Error: FTXUI headers not found in ./FTXUI/include"
    exit 3
fi

# Create build directory if it doesn't exist
if [ ! -d "$BUILD_DIR" ]; then
    echo "Creating build directory: $BUILD_DIR"
    mkdir -p "$BUILD_DIR"
fi

# Build the compilation command
COMPILE_CMD="$COMPILER"

# Add warnings if enabled
if [ "$ENABLE_WARNINGS" = true ]; then
    COMPILE_CMD="$COMPILE_CMD $WARNINGS"
fi

# Add all flags including static linking and optimizations
COMPILE_CMD="$COMPILE_CMD $OPT_LEVEL $EXTRA_OPT $STD_FLAG $THREAD_FLAG $STATIC_FLAGS $LINK_OPT $FTXUI_INCLUDE $INPUT -o $OUTPUT $FTXUI_LINK"

# Execute the compilation command
echo "Executing: $COMPILE_CMD"
$COMPILE_CMD

# If compilation succeeded, print file info
if [ $? -eq 0 ]; then
    echo "Checking executable details:"
    file "$OUTPUT"
    ls -lh "$OUTPUT"
fi

# Check compilation result
if [ $? -eq 0 ]; then
    echo "Successfully compiled $INPUT to $OUTPUT"
else
    echo "Compilation failed"
    exit 4 # Changed exit code to differentiate from file errors
fi

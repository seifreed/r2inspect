#!/bin/bash
# r2inspect Docker wrapper script for Unix/Linux/macOS
# Provides easy interface to run r2inspect in Docker container

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="r2inspect:latest"
CONTAINER_NAME="r2inspect-analysis"
SAMPLES_DIR="${SAMPLES_DIR:-./samples}"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
CONFIG_DIR="${CONFIG_DIR:-./config}"

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_message "$RED" "Error: Docker is not installed or not in PATH"
        exit 1
    fi
}

# Function to build Docker image if needed
build_image() {
    if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
        print_message "$YELLOW" "Building r2inspect Docker image..."
        docker build -t $IMAGE_NAME "$(dirname "$0")"
        print_message "$GREEN" "Docker image built successfully!"
    fi
}

# Function to create directories if they don't exist
setup_directories() {
    mkdir -p "$SAMPLES_DIR" "$OUTPUT_DIR" "$CONFIG_DIR"
    print_message "$GREEN" "Directories ready: samples/, output/, config/"
}

# Function to run r2inspect in Docker
run_analysis() {
    local args="$@"
    
    # If no arguments, show help
    if [ $# -eq 0 ]; then
        docker run --rm $IMAGE_NAME --help
        return
    fi
    
    # Check if analyzing a file
    local file_path=""
    local docker_args=""
    local r2inspect_args=""
    
    for arg in "$@"; do
        if [[ -f "$arg" ]]; then
            # It's a file, mount it
            file_path=$(realpath "$arg")
            local file_name=$(basename "$file_path")
            docker_args="$docker_args -v $file_path:/tmp/analysis/$file_name:ro"
            r2inspect_args="$r2inspect_args /tmp/analysis/$file_name"
        elif [[ -d "$arg" ]]; then
            # It's a directory, mount it
            dir_path=$(realpath "$arg")
            docker_args="$docker_args -v $dir_path:/tmp/batch:ro"
            r2inspect_args="$r2inspect_args /tmp/batch"
        else
            # It's an argument
            r2inspect_args="$r2inspect_args $arg"
        fi
    done
    
    # Run Docker container with proper mounts
    docker run --rm \
        --name $CONTAINER_NAME \
        -v "$(realpath $SAMPLES_DIR)":/home/analyst/samples:ro \
        -v "$(realpath $OUTPUT_DIR)":/home/analyst/output:rw \
        -v "$(realpath $CONFIG_DIR)":/home/analyst/config:ro \
        $docker_args \
        --cap-drop=ALL \
        --cap-add=SYS_PTRACE \
        --cap-add=DAC_READ_SEARCH \
        --security-opt=no-new-privileges:true \
        --memory=2g \
        --cpus=2 \
        $IMAGE_NAME $r2inspect_args
}

# Function to run batch analysis
run_batch() {
    local directory="${1:-$SAMPLES_DIR}"
    shift
    local args="$@"
    
    if [[ ! -d "$directory" ]]; then
        print_message "$RED" "Error: Directory $directory not found"
        exit 1
    fi
    
    print_message "$YELLOW" "Running batch analysis on $directory..."
    
    docker run --rm \
        --name $CONTAINER_NAME \
        -v "$(realpath $directory)":/home/analyst/samples:ro \
        -v "$(realpath $OUTPUT_DIR)":/home/analyst/output:rw \
        -v "$(realpath $CONFIG_DIR)":/home/analyst/config:ro \
        --cap-drop=ALL \
        --cap-add=SYS_PTRACE \
        --cap-add=DAC_READ_SEARCH \
        --security-opt=no-new-privileges:true \
        --memory=2g \
        --cpus=2 \
        $IMAGE_NAME --batch /home/analyst/samples $args -o /home/analyst/output/batch_results.csv
}

# Function to run interactive shell in container
run_shell() {
    print_message "$YELLOW" "Starting interactive shell in r2inspect container..."
    
    docker run --rm -it \
        --name $CONTAINER_NAME \
        -v "$(realpath $SAMPLES_DIR)":/home/analyst/samples:ro \
        -v "$(realpath $OUTPUT_DIR)":/home/analyst/output:rw \
        -v "$(realpath $CONFIG_DIR)":/home/analyst/config:ro \
        --cap-drop=ALL \
        --cap-add=SYS_PTRACE \
        --cap-add=DAC_READ_SEARCH \
        --security-opt=no-new-privileges:true \
        --memory=2g \
        --cpus=2 \
        --entrypoint /bin/bash \
        $IMAGE_NAME
}

# Function to clean up Docker resources
cleanup() {
    print_message "$YELLOW" "Cleaning up Docker resources..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
    print_message "$GREEN" "Cleanup complete!"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [FILE|DIRECTORY] [R2INSPECT_ARGS]

Options:
    --build         Force rebuild of Docker image
    --batch DIR     Run batch analysis on directory
    --shell         Start interactive shell in container
    --cleanup       Clean up Docker resources
    --help          Show this help message

Environment Variables:
    SAMPLES_DIR     Directory for samples (default: ./samples)
    OUTPUT_DIR      Directory for output (default: ./output)
    CONFIG_DIR      Directory for config/YARA rules (default: ./config)

Examples:
    $0 malware.exe                    # Analyze single file
    $0 --batch ./samples               # Batch analyze directory
    $0 malware.exe -j -v              # Analyze with JSON output and verbose
    $0 --shell                        # Interactive shell
    $0 --cleanup                      # Clean up resources

EOF
}

# Main script logic
main() {
    check_docker
    
    case "${1:-}" in
        --build)
            docker rmi $IMAGE_NAME 2>/dev/null || true
            build_image
            ;;
        --batch)
            shift
            setup_directories
            build_image
            run_batch "$@"
            ;;
        --shell)
            setup_directories
            build_image
            run_shell
            ;;
        --cleanup)
            cleanup
            ;;
        --help|-h)
            show_usage
            ;;
        *)
            setup_directories
            build_image
            run_analysis "$@"
            ;;
    esac
}

# Run main function
main "$@"

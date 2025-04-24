#!/bin/bash

# Hedwig Installation Script

# --- Configuration ---
REPO_OWNER="iamd3vil"
REPO_NAME="hedwig"
BINARY_NAME="hedwig"
GITHUB_API_URL="https://api.github.com"

# --- Default Values ---
VERSION="" # Will be determined if not specified
INSTALL_DIR=""
SUDO_CMD=""
OS_ARCH="" # Will be detected

# --- Helper Functions ---
print_usage() {
  echo "Usage: $0 [--version <VERSION|latest>] [--dir <INSTALL_DIR>] [-h|--help]"
  echo ""
  echo "Installs the Hedwig binary from GitHub releases."
  echo ""
  echo "Options:"
  echo "  --version <VERSION|latest> : Specify the version of Hedwig to install (e.g., 0.1.0)."
  echo "                             If set to 'latest' or omitted, the script will find the latest release."
  echo "  --dir <INSTALL_DIR>      : Specify the installation directory."
  echo "                             (default: /usr/local/bin, requires sudo if not writable)."
  echo "  -h, --help               : Show this help message."
  echo ""
  echo "Example:"
  echo "  $0                            # Install latest version to /usr/local/bin (needs sudo)"
  echo "  $0 --version latest           # Install latest version to /usr/local/bin (needs sudo)"
  echo "  $0 --version 0.1.0            # Install v0.1.0 to /usr/local/bin (needs sudo)"
  echo "  $0 --dir /path/to/my/bin      # Install latest version to a custom directory"
  echo "  $0 --version 0.1.0 --dir ~/bin # Install v0.1.0 to ~/bin"
}

check_command() {
  if ! command -v "$1" &> /dev/null; then
    echo "Error: Required command '$1' not found. Please install it and try again."
    exit 1
  fi
}

# --- OS/Arch Detection ---
detect_os_arch() {
    local os
    local arch
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux)
            os="linux"
            ;;
        Darwin)
            os="macos"
            ;;
        *)
            echo "Error: Unsupported operating system: $os"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64 | amd64)
            arch="x86_64"
            ;;
        aarch64 | arm64)
            # Assuming the release uses aarch64 for ARM64
            arch="aarch64"
            ;;
        *)
            echo "Error: Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    OS_ARCH="${os}-${arch}"
    echo "-> Detected OS/Architecture: $OS_ARCH"
}

# --- Get Latest Version ---
get_latest_version() {
    echo "-> Detecting latest version..."
    local latest_url="${GITHUB_API_URL}/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
    local tag_name

    # Try using jq if available (more robust)
    if command -v jq &> /dev/null; then
        tag_name=$(curl --silent --fail "$latest_url" | jq -r .tag_name)
        if [ $? -ne 0 ] || [ -z "$tag_name" ] || [ "$tag_name" == "null" ]; then
             echo "Warning: Failed to get latest version using jq. Trying fallback method."
             tag_name="" # Reset tag_name for fallback
        fi
    fi

    # Fallback using grep/sed if jq failed or is not installed
    if [ -z "$tag_name" ]; then
        check_command grep
        check_command sed
        # This grep/sed method is less reliable than jq
        tag_name=$(curl --silent --fail "$latest_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
         if [ $? -ne 0 ] || [ -z "$tag_name" ]; then
            echo "Error: Could not automatically detect the latest version from GitHub API ($latest_url)."
            echo "       Please specify a version using --version <VERSION>."
            exit 1
        fi
    fi

    # Remove leading 'v' if present (common practice in tags)
    VERSION="${tag_name#v}"
    echo "-> Latest version detected: $VERSION (tag: $tag_name)"
}


# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --version)
      VERSION="$2"
      shift # past argument
      shift # past value
      ;;
    --dir)
      INSTALL_DIR="$2"
      shift # past argument
      shift # past value
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *) # unknown option
      echo "Error: Unknown option: $1"
      print_usage
      exit 1
      ;;
  esac
done

# --- Detect OS/Arch ---
detect_os_arch # Sets the global OS_ARCH variable

# --- Determine Version ---
if [ -z "$VERSION" ] || [ "$VERSION" == "latest" ]; then
  get_latest_version # Sets the global VERSION variable
else
  echo "-> Using specified version: $VERSION"
fi

# --- Determine Installation Directory and Sudo Requirement ---
TARGET_DIR="/usr/local/bin" # Default target
if [ -n "$INSTALL_DIR" ]; then
  # Use user-provided directory
  TARGET_DIR="$INSTALL_DIR"
  echo "-> Using custom installation directory: $TARGET_DIR"
  # Expand ~ to home directory if present
  TARGET_DIR="${TARGET_DIR/#\~/$HOME}"
  # Check if target directory exists, create if not
  if [ ! -d "$TARGET_DIR" ]; then
      echo "-> Target directory does not exist. Attempting to create: $TARGET_DIR"
      # Check if we need sudo to create the directory
      PARENT_DIR=$(dirname "$TARGET_DIR")
      if [ ! -w "$PARENT_DIR" ] && [ "$(id -u)" != "0" ]; then
          check_command sudo
          SUDO_CMD="sudo"
          echo "-> Parent directory '$PARENT_DIR' not writable. Using sudo to create target directory."
      fi
      $SUDO_CMD mkdir -p "$TARGET_DIR"
      if [ $? -ne 0 ]; then
          echo "Error: Failed to create directory $TARGET_DIR."
          exit 1
      fi
      echo "-> Successfully created directory: $TARGET_DIR"
      # Reset SUDO_CMD, we only needed it for mkdir potentially
      SUDO_CMD=""
  fi
   # Check if we need sudo to write *into* the target directory
  if [ ! -w "$TARGET_DIR" ] && [ "$(id -u)" != "0" ]; then
      check_command sudo
      SUDO_CMD="sudo"
      echo "-> Write permission required for $TARGET_DIR. Will use sudo for installation."
  fi
else
  # Use default directory
  echo "-> Using default installation directory: $TARGET_DIR"
   # Check if default target directory exists (it usually does)
   if [ ! -d "$TARGET_DIR" ]; then
       echo "Error: Default directory $TARGET_DIR does not exist."
       exit 1
   fi
  # Check if we need sudo for the default directory
  if [ ! -w "$TARGET_DIR" ] && [ "$(id -u)" != "0" ]; then
      check_command sudo
      SUDO_CMD="sudo"
      echo "-> Write permission required for $TARGET_DIR. Will use sudo for installation."
  fi
fi

# --- Check Dependencies ---
echo "-> Checking for required tools..."
check_command curl
check_command unzip
check_command mktemp
check_command uname
# jq is optional for latest version detection but preferred
if ! command -v jq &> /dev/null; then
    echo "-> Optional tool 'jq' not found. Using fallback for latest version detection."
    # Check for fallback tools if jq isn't present and latest version is requested
    if [ -z "$VERSION" ] || [ "$VERSION" == "latest" ]; then
        check_command grep
        check_command sed
    fi
fi


# --- Installation ---
# Construct download URL
RELEASE_TAG="v${VERSION}" # Add 'v' prefix back for the tag
ZIP_FILENAME="${BINARY_NAME}-${RELEASE_TAG}-${OS_ARCH}.zip"
DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}/${ZIP_FILENAME}"

# Create a temporary directory
TMP_DIR=$(mktemp -d -t hedwig-install-XXXXXX)
if [ ! -d "$TMP_DIR" ]; then
    echo "Error: Could not create temporary directory."
    exit 1
fi
# Ensure cleanup on exit (removes the temp dir)
trap 'echo "-> Cleaning up temporary files..."; rm -rf -- "$TMP_DIR"' EXIT

echo "-> Downloading Hedwig version $VERSION ($OS_ARCH)..."
echo "   From: $DOWNLOAD_URL"
curl --fail --silent --location -o "$TMP_DIR/$ZIP_FILENAME" "$DOWNLOAD_URL"
if [ $? -ne 0 ]; then
  echo "Error: Failed to download Hedwig from $DOWNLOAD_URL."
  echo "       Please check the version number, OS/Architecture ($OS_ARCH), and your internet connection."
  exit 1
fi
echo "-> Download complete."

echo "-> Unzipping $ZIP_FILENAME..."
unzip -q "$TMP_DIR/$ZIP_FILENAME" -d "$TMP_DIR"
if [ $? -ne 0 ]; then
  echo "Error: Failed to unzip $ZIP_FILENAME."
  exit 1
fi

# Find the binary (it might be directly in the zip or in a subdirectory)
EXTRACTED_BINARY="$TMP_DIR/$BINARY_NAME"
if [ ! -f "$EXTRACTED_BINARY" ]; then
    # Check common pattern: <repo>-<tag>-<arch>/<binary>
    # Example: hedwig-v0.1.0-linux-x86_64/hedwig
    EXTRACTED_BINARY_IN_DIR="$TMP_DIR/${BINARY_NAME}-${RELEASE_TAG}-${OS_ARCH}/${BINARY_NAME}"
     if [ -f "$EXTRACTED_BINARY_IN_DIR" ]; then
        EXTRACTED_BINARY="$EXTRACTED_BINARY_IN_DIR"
     else
        # Fallback: just find the binary named 'hedwig' anywhere in the temp dir
        FOUND_BINARY=$(find "$TMP_DIR" -name "$BINARY_NAME" -type f -print -quit)
        if [ -n "$FOUND_BINARY" ] && [ -f "$FOUND_BINARY" ]; then
             EXTRACTED_BINARY="$FOUND_BINARY"
        else
             echo "Error: Could not find '$BINARY_NAME' binary within the unzipped archive."
             echo "       Contents of temporary directory '$TMP_DIR':"
             ls -lR "$TMP_DIR"
             exit 1
        fi
     fi
fi
echo "-> Found binary at: $EXTRACTED_BINARY"

echo "-> Making $BINARY_NAME executable..."
chmod +x "$EXTRACTED_BINARY"
if [ $? -ne 0 ]; then
  echo "Error: Failed to set execute permission on $EXTRACTED_BINARY."
  exit 1
fi

INSTALL_PATH="$TARGET_DIR/$BINARY_NAME"
echo "-> Installing $BINARY_NAME to $INSTALL_PATH..."
$SUDO_CMD mv "$EXTRACTED_BINARY" "$INSTALL_PATH"
if [ $? -ne 0 ]; then
  echo "Error: Failed to move $BINARY_NAME to $INSTALL_PATH."
  echo "       Please check permissions for $TARGET_DIR or try using sudo if applicable."
  exit 1
fi

# Verify installation
# Check if the target directory is in PATH
if [[ ":$PATH:" == *":$TARGET_DIR:"* ]] && command -v "$BINARY_NAME" &> /dev/null && [ "$(command -v "$BINARY_NAME")" == "$INSTALL_PATH" ]; then
    echo ""
    echo "✅ Hedwig version $VERSION installed successfully to $INSTALL_PATH and is in your PATH."
    echo "   You can now run 'hedwig --version' to verify."
elif [ -x "$INSTALL_PATH" ]; then
     echo ""
     echo "✅ Hedwig version $VERSION installed successfully to $INSTALL_PATH."
     if [[ ":$PATH:" != *":$TARGET_DIR:"* ]]; then
         echo "   However, '$TARGET_DIR' might not be in your system's PATH."
         echo "   You may need to add it to your PATH environment variable."
         echo "   Example for bash/zsh (add to ~/.bashrc or ~/.zshrc and restart your shell):"
         echo "   export PATH=\"$TARGET_DIR:\$PATH\""
     fi
     echo "   You can run it directly using: $INSTALL_PATH --version"
else
    echo ""
    echo "❌ Installation failed or verification check encountered an issue."
    echo "   Hedwig binary might be at $INSTALL_PATH, but could not be verified."
fi

# Trap will handle cleanup
exit 0

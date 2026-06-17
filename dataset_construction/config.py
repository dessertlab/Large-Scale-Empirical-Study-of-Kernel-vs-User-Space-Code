# File extensions to process
C_CPP_EXTENSIONS = {
    '.c', '.cpp', '.cc', '.cxx', 
    '.h', '.hpp', '.hh', '.hxx', 
    '.ixx', '.cppm', '.hppm'
}
 
# Directories to exclude (case-insensitive)
EXCLUDED_DIRS = {
   
    "android", "java", "node_modules", "python", "site-packages", ".venv", "env",
    "build", "cmake-build-debug", "cmake-build-release", "out", "bin", "obj", 
    "x64", "x86", "arm", "arm64", ".vs", "artifacts",
    "vcpkg_installed", ".conan", "third_party", "thirdparty", "external", "deps",
    ".git", ".github", ".idea", ".vscode",
    "docs", "documentation", "html", "site", "assets", "images", "media",
    "tests", "test", "testing", "benchmarks", "perf"
}
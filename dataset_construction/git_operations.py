"""Git repository operations."""

import os
import subprocess


GIT_CLONE_DEPTH = 1


def clone_repository(url, destination):
    """Clone a git repository with optimized settings."""
    dest_normal = os.path.abspath(destination)
    print(f"  ├─ Cloning: {url}")

    try:
        result = subprocess.run(
            [
                "git", "clone",
                "--depth", str(GIT_CLONE_DEPTH),
                "--filter=blob:none",
                "--config", "core.longpaths=true",
                "--single-branch",
                "--no-tags",
                url,
                dest_normal,
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(f"  ├─ ✅ Clone successful")
            return True

        print(f"  ├─ ❌ Clone failed: {result.stderr}")
        return False

    except subprocess.TimeoutExpired:
        print("  ├─ ⏱️ Clone timeout expired")
        return False
    except Exception as e:
        print(f"  ├─ ❌ Clone error: {str(e)}")
        return False


def clone_repository_sparse(url, destination, folders):
    """Clone a git repository with sparse checkout for specific folders.
    
    Args:
        url: Git repository URL
        destination: Full path where to clone (e.g., samples/kernel/linux)
        folders: List of folders to checkout (e.g., ['kernel'])
    """
    dest_normal = os.path.abspath(destination)
    print(f"  ├─ Cloning (sparse): {url}")
    print(f"  ├─ Folders: {', '.join(folders)}")

    try:
        # Initialize empty repository
        result = subprocess.run(
            ["git", "init", dest_normal],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            print(f"  ├─ ❌ Init failed: {result.stderr}")
            return False

        # Change to repository directory
        original_dir = os.getcwd()
        os.chdir(dest_normal)

        try:
            # Add remote
            subprocess.run(
                ["git", "remote", "add", "origin", url],
                capture_output=True,
                text=True,
                timeout=30,
                check=True
            )

            # Enable sparse checkout
            subprocess.run(
                ["git", "config", "core.sparseCheckout", "true"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True
            )

            subprocess.run(
                ["git", "config", "core.longpaths", "true"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True
            )

            # Write sparse checkout patterns
            # Include only specified folders and their contents
            sparse_file = os.path.join(".git", "info", "sparse-checkout")
            os.makedirs(os.path.dirname(sparse_file), exist_ok=True)
            with open(sparse_file, "w") as f:
                for folder in folders:
                    # Remove trailing slash if present
                    folder = folder.rstrip('/')
                    # Include the folder and all its contents
                    f.write(f"{folder}/**\n")

            # Fetch with depth and filter
            result = subprocess.run(
                [
                    "git", "fetch",
                    "--depth", str(GIT_CLONE_DEPTH),
                    "--filter=blob:none",
                    "origin", "master"
                ],
                capture_output=True,
                text=True
            )

            # Try main branch if master fails
            if result.returncode != 0:
                result = subprocess.run(
                    [
                        "git", "fetch",
                        "--depth", str(GIT_CLONE_DEPTH),
                        "--filter=blob:none",
                        "origin", "main"
                    ],
                    capture_output=True,
                    text=True
                )

            if result.returncode != 0:
                print(f"  ├─ ❌ Fetch failed: {result.stderr}")
                os.chdir(original_dir)
                return False

            # Checkout the fetched branch
            result = subprocess.run(
                ["git", "checkout", "FETCH_HEAD"],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                os.chdir(original_dir)
                print(f"  ├─ ✅ Sparse clone successful")
                print(f"  ├─ Cloned to: {dest_normal}")
                return True

            os.chdir(original_dir)
            print(f"  ├─ ❌ Checkout failed: {result.stderr}")
            return False

        except Exception as e:
            os.chdir(original_dir)
            raise e

    except subprocess.TimeoutExpired:
        print("  ├─ ⏱️ Clone timeout expired")
        return False
    except Exception as e:
        print(f"  ├─ ❌ Clone error: {str(e)}")
        return False

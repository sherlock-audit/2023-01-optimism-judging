import os


def main():
    added_files = os.environ.get("ADDED_FILES")
    modified_files = os.environ.get("MODIFIED_FILES")
    renamed_files = os.environ.get("RENAMED_FILES")
    removed_files = os.environ.get("REMOVED_FILES")

    if added_files != "":
        added_files = [
            x
            for x in added_files.split(" ")
            if not any(
                y in x
                for y in [".data", ".git", ".github", "README.md", "Audit_Report.pdf"]
            )
        ]
    else:
        added_files = []

    if modified_files != "":
        modified_files = [
            x
            for x in modified_files.split(" ")
            if not any(
                y in x
                for y in [".data", ".git", ".github", "README.md", "Audit_Report.pdf"]
            )
        ]
    else:
        modified_files = []

    if renamed_files != "":
        renamed_files = [
            x
            for x in renamed_files.split(" ")
            if not any(
                y in x
                for y in [".data", ".git", ".github", "README.md", "Audit_Report.pdf"]
            )
        ]
    else:
        renamed_files = []

    if removed_files != "":
        removed_files = [
            x
            for x in removed_files.split(" ")
            if not any(
                y in x
                for y in [".data", ".git", ".github", "README.md", "Audit_Report.pdf"]
            )
        ]
    else:
        removed_files = []

    print("MODIFIED FILES")
    print(modified_files)

    if len(modified_files) > 0:
        print("❌ File contents should not be altered.")
        exit(1)

    print("✅ File contents have not be altered.")


if __name__ == "__main__":
    main()
import os
from pprint import pprint


def print_directory_structure(startpath, indent=""):
    print(f"{indent}{os.path.basename(startpath)}/")
    indent += "    "
    for entry in os.listdir(startpath):
        abspath = os.path.join(startpath, entry)
        if os.path.isdir(abspath):
            print_directory_structure(abspath, indent)
        else:
            print(f"{indent}{entry}")


if __name__ == "__main__":
    current_dir = os.getcwd()
    pprint(f"Current working directory: {current_dir}")
    pprint("\nDirectory structure:")
    print_directory_structure(current_dir)

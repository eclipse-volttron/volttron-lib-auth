import subprocess

import tomli

skip_list = ['python', 'poetry']


def get_latest_version(pkg, group: str = None):
    if group is not None:
        print(f"Updating {pkg} in group {group}")
    else:
        print(f"Updating {pkg}")

    cmd = f"poetry add {pkg}@latest".split()
    if group is not None:
        cmd.extend(f"--group {group}".split())
    result = subprocess.call(cmd)
    if result == 0:
        print(f"Successfully updated {pkg}")
    else:
        print(f"Failed to update {pkg}")


def update_dependencies(group: str = None):
    with open("pyproject.toml", 'rb') as f:
        data = tomli.load(f)

    root = data["tool"]["poetry"]

    if group is not None:
        if root["group"][group]['dependencies']:
            root = root["group"][group]['dependencies']
        else:
            print(f"Unknown group {group}")
            return
    else:
        root = root["dependencies"]

    for pkg in root:
        if pkg not in skip_list:
            get_latest_version(pkg=pkg, group=group)
        else:
            print(f"Skipping {pkg}")

    # cmd = "poetry show".split()
    # result = subprocess.check_output(cmd).decode("utf-8")


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="Update dependencies")

    parser.add_argument("--dev", help="Update the dev dependency group", action="store_true", default=False)

    opts = parser.parse_args()
    if opts.dev:
        update_dependencies("dev")
    else:
        update_dependencies()

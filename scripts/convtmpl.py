"""Convert this template repo to a named Python project.

This file deletes itself after it has successfully executed.

Requires a single argument, the name of the Python project we will use.
This name must be a valid Python symbol.

Put any value as a second argument to stop this file from self deleting.
"""


import argparse
import datetime
import re
import os
import sys


NAME_RE = re.compile(r"\{\{NAME\}\}")
AUTHOR_RE = re.compile(r"\{\{AUTHOR\}\}")
YEAR_RE = re.compile(r"\{\{YEAR\}\}")
GHBASE_RE = re.compile(r"\{\{GHBASE\}\}")
DOCSBASE_RE = re.compile(r"\{\{DOCSBASE\}\}")

PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PARSER = argparse.ArgumentParser(
    description="Convert this Python project template into a named Python project."
)
PARSER.add_argument(
    "name",
    help="The name to use for the new Python project. Must be a valid Python name.",
)
PARSER.add_argument(
    "--author",
    help="The name of the author to use for this project.",
    default="John Gorman",
)
PARSER.add_argument(
    "--gh-base",
    help="The base URL to point to this project's repo.",
    default="https://github.com/gormaniac",
)
PARSER.add_argument(
    "--docs-base",
    help="The base URL to point to this project's documentation.",
    default="https://gormo.co",
)
PARSER.add_argument(
    "--delete",
    help="Delete this script after execution.",
    action="store_true",
)


def delete_self():
    """Delete this file."""

    os.remove(os.path.abspath(__file__))


def rename_package(new_name: str):
    """Rename the folder `src/{{NAME}}`."""

    old_dir_name = "src/{{NAME}}"
    old_dir = os.path.join(PARENT_DIR, old_dir_name)
    new_dir_name = NAME_RE.sub(new_name, old_dir_name)
    new_dir = os.path.join(PARENT_DIR, new_dir_name)

    try:
        os.rename(old_dir, new_dir)
    except OSError as e:
        print(f"Unable to rename the src dir: {e}")
        sys.exit(1)


def replace_vals(
    name,
    author,
    year,
    gh_base,
    docs_base,
):
    """Walk __file__'s parent dir and replace all instances of `{{NAME}}`.

    Also replaces other values in files based on *_RE regex expressions.
    """

    for dpath, _, fnames in os.walk(PARENT_DIR):
        if (".git" in dpath) or ("scripts" in dpath):
            continue

        for fname in fnames:
            fullpath = os.path.join(dpath, fname)
            try:
                with open(fullpath, "r") as fd:
                    fdata = fd.read()
                with open(fullpath, "w") as fd:
                    fdata = NAME_RE.sub(name, fdata)
                    fdata = AUTHOR_RE.sub(author, fdata)
                    fdata = YEAR_RE.sub(year, fdata)
                    fdata = GHBASE_RE.sub(gh_base, fdata)
                    fdata = DOCSBASE_RE.sub(docs_base, fdata)
                    fd.write(fdata)
            except (IOError, re.error) as e:
                print(f"Unable to rename values in {fullpath}: {e}")


def main():
    """The main function."""

    args = PARSER.parse_args()

    rename_package(args.name)
    replace_vals(
        name=args.name,
        author=args.author,
        docs_base=args.docs_base,
        gh_base=args.gh_base,
        year=str(datetime.datetime.now().year),
    )

    if args.delete:
        delete_self()


if __name__ == "__main__":
    main()

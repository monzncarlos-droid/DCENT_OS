#!/usr/bin/env python3
"""Prove every scripts/test_*.sh suite has an active release-gate path.

Raw basename searches are unsafe here: comments, syntax-only checks, and
`require_pattern` arguments can all mention a test without executing it. This
scanner recognizes active `sh`/`bash` commands, follows variable-bound test
delegation between shell suites, and admits exact workflow `run:` commands.
"""

from __future__ import annotations

import re
import shlex
import sys
from collections import deque
from pathlib import Path


SHELLS = {"sh", "bash"}
COMMAND_BOUNDARIES = {";", ";;", "&", "&&", "|", "||", "(", ")"}
COMMAND_PREFIXES = {"if", "elif", "while", "until", "then", "else", "do", "!", "{"}
COMMAND_WRAPPERS = {"command", "exec", "env", "nice", "nohup", "sudo", "timeout"}
TEST_NAME = re.compile(r"(?:^|/)(test_[A-Za-z0-9_.-]+\.sh)$")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
VARIABLE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")
WORKFLOW_COMMAND = re.compile(
    r"^\s*(?:run:\s*)?(?:sh|bash)\s+(?P<target>[^\s#]*test_[A-Za-z0-9_.-]+\.sh)(?:\s|$)"
)


def shell_tokens(source: str) -> list[str]:
    lexer = shlex.shlex(source, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    return list(lexer)


def referenced_test_name(value: str, known: set[str]) -> str | None:
    match = TEST_NAME.search(value.replace("\\", "/"))
    if match and match.group(1) in known:
        return match.group(1)
    return None


def command_shell_edges(
    tokens: list[str], bindings: dict[str, str], known: set[str]
) -> set[str]:
    """Recognize shell interpreters only where the shell grammar executes a command.

    This deliberately accepts a narrow, auditable subset. A future invocation
    with exotic shell syntax should make its suite fail the anti-orphan gate
    until this parser and its negative controls are extended together.
    """
    edges: set[str] = set()
    command_expected = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in COMMAND_BOUNDARIES:
            command_expected = True
            index += 1
            continue
        if not command_expected:
            index += 1
            continue
        if token in COMMAND_PREFIXES:
            index += 1
            continue
        if ASSIGNMENT.match(token):
            index += 1
            continue
        if token in COMMAND_WRAPPERS:
            index += 1
            while index < len(tokens) and (
                tokens[index].startswith("-") or ASSIGNMENT.match(tokens[index])
            ):
                index += 1
            continue
        if token not in SHELLS:
            command_expected = False
            index += 1
            continue

        cursor = index + 1
        options: list[str] = []
        while cursor < len(tokens) and tokens[cursor].startswith("-"):
            options.append(tokens[cursor])
            cursor += 1
        if "-n" not in options and not {"-c", "-lc"}.intersection(options) and cursor < len(tokens):
            target_token = tokens[cursor]
            variable = VARIABLE.match(target_token)
            if variable:
                target = bindings.get(variable.group(1) or variable.group(2))
            else:
                target = referenced_test_name(target_token, known)
            if target is not None:
                edges.add(target)
        command_expected = False
        index = cursor + 1
    return edges


def shell_test_edges(source: str, known: set[str]) -> set[str]:
    bindings: dict[str, str] = {}
    # Collect VAR=test_name.sh bindings line by line, tolerating an individual
    # unparseable line (heredoc body, $'...', or an apostrophe) exactly as the
    # edge scan below already does. Tokenizing the whole source at once aborted
    # the entire reachability gate the moment any walked script contained a
    # shlex-unbalanced quote, which is common in real shell.
    for line in source.splitlines():
        try:
            line_tokens = shell_tokens(line)
        except ValueError:
            continue
        for token in line_tokens:
            assignment = ASSIGNMENT.match(token)
            if not assignment:
                continue
            target = referenced_test_name(assignment.group(2), known)
            if target is not None:
                bindings[assignment.group(1)] = target

    edges: set[str] = set()
    # Scan physical command lines independently so a command word on the next
    # line is not mistaken for an argument of the previous command. Existing
    # gate invocations intentionally keep interpreter + target on one line.
    for line in source.splitlines():
        try:
            line_tokens = shell_tokens(line)
        except ValueError:
            # Quoted/here-document continuations are not admitted as execution
            # proof. The suite remains unreachable unless another explicit
            # single-line invocation exists.
            continue
        edges.update(command_shell_edges(line_tokens, bindings, known))
    return edges


def workflow_test_edges(source: str, known: set[str]) -> set[str]:
    edges: set[str] = set()
    for line in source.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = WORKFLOW_COMMAND.match(line)
        if not match:
            continue
        target = referenced_test_name(match.group("target"), known)
        if target is not None:
            edges.add(target)
    return edges


def self_test() -> int:
    known = {
        "test_direct.sh",
        "test_parent.sh",
        "test_child.sh",
        "test_comment.sh",
        "test_pattern.sh",
        "test_syntax.sh",
        "test_workflow.sh",
        "test_argument.sh",
    }
    root = """
        # sh scripts/test_comment.sh
        require_pattern file 'sh scripts/test_pattern.sh' message
        printf sh scripts/test_argument.sh
        echo sh scripts/test_argument.sh
        require_pattern file sh scripts/test_argument.sh
        env printf sh scripts/test_argument.sh
        sh -n scripts/test_syntax.sh
        DCENT_TEST_MODE=1 sh scripts/test_direct.sh
        if sh scripts/test_direct.sh; then :; fi
        if sh scripts/test_parent.sh; then :; fi
    """
    parent = """
        CHILD="$SCRIPT_DIR/test_child.sh"
        if false; then :
        elif sh "$CHILD"; then :
        fi
    """
    assert shell_test_edges(root, known) == {"test_direct.sh", "test_parent.sh"}
    assert shell_test_edges(parent, known) == {"test_child.sh"}
    workflow = """
      # run: sh scripts/test_comment.sh
      - name: exact proof
        run: sh scripts/test_workflow.sh
    """
    assert workflow_test_edges(workflow, known) == {"test_workflow.sh"}
    print("shell test reachability self-test passed")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:]:
        print("usage: check_test_gate_reachability.py [--self-test]", file=sys.stderr)
        return 2

    project = Path(__file__).resolve().parent.parent
    scripts_dir = project / "scripts"
    tests = sorted(scripts_dir.rglob("test_*.sh"))
    by_name = {path.name: path for path in tests}
    if len(by_name) != len(tests):
        duplicates = sorted(name for name in by_name if sum(p.name == name for p in tests) > 1)
        print(f"FAIL: duplicate safety-test basenames are ambiguous: {', '.join(duplicates)}", file=sys.stderr)
        return 1
    known = set(by_name)

    root = scripts_dir / "ci_offline_gates.sh"
    graph: dict[str, set[str]] = {
        "<offline-gate>": shell_test_edges(root.read_text(encoding="utf-8"), known)
    }
    for name, path in by_name.items():
        graph[name] = shell_test_edges(path.read_text(encoding="utf-8"), known)

    workflow_root = project.parent.parent / ".github" / "workflows"
    workflow_seeds: set[str] = set()
    for workflow in sorted(workflow_root.glob("*.yml")):
        workflow_seeds.update(workflow_test_edges(workflow.read_text(encoding="utf-8"), known))

    reachable = set(workflow_seeds)
    queue: deque[str] = deque(["<offline-gate>", *sorted(workflow_seeds)])
    seen = set(queue)
    while queue:
        source = queue.popleft()
        for target in graph.get(source, set()):
            reachable.add(target)
            if target not in seen:
                seen.add(target)
                queue.append(target)

    missing = sorted(known - reachable)
    if missing:
        for name in missing:
            relative = by_name[name].relative_to(project).as_posix()
            print(
                f"FAIL: {relative} has no active offline-gate, transitive-suite, or workflow invocation",
                file=sys.stderr,
            )
        return 1

    print(
        f"shell test reachability passed: {len(reachable)}/{len(known)} safety suites have active gate paths"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

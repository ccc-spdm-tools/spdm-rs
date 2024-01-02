#
# Copyright (c) 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0 or MIT
#

import subprocess
import threading
import os
import re
import time
import queue


def parse_number(s: str, pattern: re.Pattern) -> int:
    match = re.search(pattern, s, re.DOTALL)
    assert match
    value = match.group(1)
    return int(value)


def run_exec(shell_cmd: str, result_queue) -> str:
    r = subprocess.run(shell_cmd, shell=True, stdout=subprocess.PIPE, )
    out = r.stdout.decode().strip()
    result_queue.put(out)
    return out


def memory_usage(name, requester_cmd, responder_cmd) -> (str, int, int, int):
    result_responder = queue.Queue()
    result_requester = queue.Queue()

    responder = threading.Thread(
        target=run_exec, args=(responder_cmd, result_responder))
    responder.start()
    time.sleep(10)
    requester = threading.Thread(
        target=run_exec, args=(requester_cmd, result_requester))
    requester.start()

    requester.join()
    responder.join()

    out_responder = result_responder.get()
    out_requester = result_requester.get()

    max_stack_usage_responder = parse_number(
        out_responder, r"max stack usage: (\d+)")
    max_heap_usage_responder = parse_number(
        out_responder, r"max heap usage: (\d+)")
    max_stack_usage_requester = parse_number(
        out_requester, r"max stack usage: (\d+)")
    max_heap_usage_requester = parse_number(
        out_requester, r"max heap usage: (\d+)")

    return (name, max_stack_usage_requester, max_heap_usage_requester, max_stack_usage_responder, max_heap_usage_responder)


def main():
    test_vector = [
        (
            "async-executor + release                ",
            "cargo run --release -p spdm-requester-emu --no-default-features --features=spdm-ring,hashed-transcript-data,async-executor,test_stack_size,test_heap_size",
            "cargo run --release -p spdm-responder-emu --no-default-features --features=spdm-ring,hashed-transcript-data,async-executor,test_stack_size,test_heap_size"
        ),
        (
            "async-tokio + release                   ",
            "cargo run --release -p spdm-requester-emu --no-default-features --features=spdm-ring,hashed-transcript-data,async-tokio,test_stack_size,test_heap_size",
            "cargo run --release -p spdm-responder-emu --no-default-features --features=spdm-ring,hashed-transcript-data,async-tokio,test_stack_size,test_heap_size"
        ),
        (
            "async-executor + releas + raw transcript",
            "cargo run --release -p spdm-requester-emu --no-default-features --features=spdm-ring,async-executor,test_stack_size,test_heap_size",
            "cargo run --release -p spdm-responder-emu --no-default-features --features=spdm-ring,async-executor,test_stack_size,test_heap_size"
        ),
        (
            "sync + release                          ",
            "cargo run --release -p spdm-requester-emu --no-default-features --features=spdm-ring,hashed-transcript-data,test_stack_size,test_heap_size,is_sync",
            "cargo run --release -p spdm-responder-emu --no-default-features --features=spdm-ring,hashed-transcript-data,test_stack_size,test_heap_size,is_sync"
        ),
        (
            "sync + release + raw transcript         ",
            "cargo run --release -p spdm-requester-emu --no-default-features --features=spdm-ring,test_stack_size,test_heap_size,is_sync",
            "cargo run --release -p spdm-responder-emu --no-default-features --features=spdm-ring,test_stack_size,test_heap_size,is_sync"
        ),

        (
            "async-executor + debug                  ",
            "cargo run -p spdm-requester-emu --no-default-features --features=spdm-ring,hashed-transcript-data,async-executor,test_stack_size,test_heap_size",
            "cargo run -p spdm-responder-emu --no-default-features --features=spdm-ring,hashed-transcript-data,async-executor,test_stack_size,test_heap_size"
        ),

        (
            "sync + debug                            ",
            "cargo run -p spdm-requester-emu --no-default-features --features=spdm-ring,hashed-transcript-data,test_stack_size,test_heap_size,is_sync",
            "cargo run -p spdm-responder-emu --no-default-features --features=spdm-ring,hashed-transcript-data,test_stack_size,test_heap_size,is_sync"
        ),

    ]
    results = []
    for t in test_vector:
        result = memory_usage(*t)
        results.append(result)

    print("""
|                                        |      Requester        |      Responder        |
|                                        | stack     |  heap     | stack     |  heap     |
| -------------------------------------- |-----------|-----------|-----------|-----------|""")
    for r in results:
        print(
            "|{}| {:10}| {:10}| {:10}| {:10}|".format(*r))


if __name__ == "__main__":
    main()

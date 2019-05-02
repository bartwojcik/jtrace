#!/usr/bin/env python

import os


def fork_bomb(num):
    pid = os.fork()
    if pid == 0:
        if num > 0:
            fork_bomb(num - 1)
    else:
        print(f'[fork-test] Created child process with PID {pid}')
        ret_code = os.waitpid(pid, 0)
        print(f'[fork-test] Process {ret_code[0]} returned code {ret_code[1]}')


if __name__ == '__main__':
    fork_bomb(2)

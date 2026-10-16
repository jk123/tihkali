# tihkali

Nano BSD-style OS in Rust (+asm). See `AGENTS.md` for the full architecture
and rules.

## Working in two sessions

Two MiMoCode agents work this repo at once, each in its own git worktree so
they never collide on `target/` or the initramfs lock.

| | worktree | branch | tmux session | launch |
|---|---|---|---|---|
| A | `~/projects/tihkali` | `master` | `mimoa` | `mimoa` |
| B | `~/projects/tihkali-b` | `side-b` | `mimob` | `tmux attach -t mimob` |

Open session A with `mimoa`, session B with `tmux attach -t mimob`.

Detach without killing the session: `Ctrl-b` then `d`.

Check which is live:

```sh
tmux ls
git worktree list
```

`side-b` is checked out in the B worktree, so you can't `git checkout
side-b` in A — work in that directory instead:

```sh
cd ~/projects/tihkali-b
```

## Git

One remote, `origin` → `github.com/jk123/tihkali.git`. Use it for
everything.

Never run concurrent `./tools/check.sh` — sessions must stay sequential.
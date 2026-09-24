#!/usr/bin/env python3
"""check_workflow.py - validate .github/workflows/ci.yml beyond what PyYAML safe_load does.

Why: a duplicate mapping key (e.g. two `shell:` or two `run:` in the same step) makes GitHub
reject the whole workflow (the run gets jobs=0), while PyYAML silently keeps the last one.
That exact mistake was made three times in this repo by editing only a step HEADER and leaving
the old `shell:`/`run:` lines behind (STATUS #501/#502/#514). This checker raises on any
duplicate key and also asserts the job/step shapes we rely on.
"""
import sys
import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    keys = set()
    out = {}
    for k, v in node.value:
        kk = loader.construct_object(k, deep=deep)
        if kk in keys:
            raise ValueError("duplicate key %r at line %d" % (kk, k.start_mark.line + 1))
        keys.add(kk)
        out[kk] = loader.construct_object(v, deep=deep)
    return out


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def main(path):
    with open(path, encoding="utf-8") as f:
        doc = yaml.load(f, Loader=StrictLoader)
    jobs = doc.get("jobs") or {}
    for jname, job in jobs.items():
        steps = job.get("steps") or []
        for i, s in enumerate(steps):
            # A step may legally be `- uses: ...` with no name, so do not require one.
            if "run" in s and "uses" in s:
                raise ValueError("job %s step %d mixes run and uses" % (jname, i))
    print("workflow OK: jobs=%d" % len(jobs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/ci.yml"))

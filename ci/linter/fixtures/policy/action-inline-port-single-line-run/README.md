# action-inline-port-single-line-run

Action `a` claims 18500 from a SINGLE-LINE `run:` scalar; action `b` claims
18500 and 18501 as two assignments sharing ONE line.

Both shapes defeated the earlier approach, which matched against `_body()` --
the node re-serialized by `yaml.safe_dump`. A single-line `run:` dumps as a
bare scalar, so no anchor reached it and the collision passed green; and a
single regex cannot report two assignments on one line, because matches may
not overlap and the first consumes the prefix the second needs.

Matching each step's raw `run:` text and walking the assignment prefix per
line handles both.

Expected: exit 1, the cross-action collision on 18500 reported.

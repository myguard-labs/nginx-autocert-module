# action-inline-port-prefixed-identifier

One action claims `AC_TEST_PORT=18500` exactly once. The same step also stores
the value in a prefixed variable, leaves an old band commented out, and echoes
the value in a diagnostic:

    AC_TEST_PORT=18500
    SAVED_AC_TEST_PORT=18500
    # AC_TEST_PORT=18500
    echo "using AC_TEST_PORT=18500"

None of the last three claims a port. An `INLINE_PORT_RE` that matches the bare
token folds them into the uniqueness set as phantom second claimants, and the
action is reported as claiming 18500 twice -- a false collision on a correct
tree. Requiring a statement boundary rejects all three while still matching the
real assignment, including the mid-line form a single-quoted scalar produces.

Expected: exit 0, one band, no findings.

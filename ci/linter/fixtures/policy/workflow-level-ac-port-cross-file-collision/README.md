# fixture: workflow-level-ac-port-cross-file-collision

Workflow-level `AC_TEST_PORT[0-9]*` declarations claim bands just like inline
shell assignments. The 19901 pair puts the workflow-level declaration first;
the 19902 pair puts the inline declaration first. Both must report collisions.

Keeping both orderings prevents registration from working only when the
workflow-level declaration happens to be the first claimant.

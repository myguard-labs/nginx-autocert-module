# fixture: action-band-collision

Two distinct composite actions, `.github/actions/first/action.yml` and
`.github/actions/second/action.yml`, both declare `TEST_BASE_PORT: '19830'`.
Every composite action file is named `action.yml`, so `where` built from just
`path.name` names the same string ("action.yml") for both sides of the
collision and identifies neither offending action.

`ports` must go red naming the port and BOTH actions by a path distinguishing
them (e.g. `actions/first/action.yml` vs `actions/second/action.yml`), not by
the bare, ambiguous "action.yml" repeated twice.

Actions: `.github/actions/first/action.yml`, `.github/actions/second/action.yml`.

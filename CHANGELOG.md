# Changelog

## 4.3.0 - 2025-05-18

- Updated legotapas to v1.7.0

## 4.2.0 - 2023-06-01

- Update lego to v4.12.0

## 4.1.0 - 2022-02-21

- Switched library used for environment variables. Should have no user-visible impact.
- Update to legotapas v1.1.0
- Now renews certificates if they expire within 30 days instead of 7.

## 4.0.0 - 2021-10-15

- Switched to using [legotapas](https://github.com/csmith/legotapas) to provide build constraints
  for DNS providers.
  - **Breaking:** Previously building with the `httpreq` tag would produce a small binary with
    only support for the httpreq DNS provider. This build tag has now changed to `lego_httpreq`.
  - Builds specific to any other DNS provider can now be created with corresponding build
    constraints.

## 3.1.2 - 2021-09-19

- Fixed "insufficient permissions" check STILL being completely wrong if files hadn't already
  been created.

## 3.1.1 - 2021-09-19

- Fixed "insufficient permissions" check being completely wrong if files hadn't already
  been created.

## 3.1.0 - 2021-09-19

- Fixed "insufficient permissions" error not printing a new line at the end.
- Added more detail to insufficient permission errors.

## 3.0.0 - 2021-09-16

- certwrapper will now exit if it can't write to any of the required paths before attempting to
  obtain a certificate.
- Update to Go 1.17
- Support for building with only support for httpreq endpoints. This shaves about 30MB off the binary size. 

## 2.0.0 - 2021-07-26

- Configuration of certwrapper can now be done using environment variables.

## 1.0.0 - 2021-06-17

_Initial release._

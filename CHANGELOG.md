# Unreleased

# v4.0.0

- Switched to using [legotapas](https://github.com/csmith/legotapas) to provide build constraints
  for DNS providers.
  - **Breaking:** Previously building with the `httpreq` tag would produce a small binary with
    only support for the httpreq DNS provider. This build tag has now changed to `lego_httpreq`.
  - Builds specific to any other DNS provider can now be created with corresponding build
    constraints.

# v3.1.2

- Fixed "insufficient permissions" check STILL being completely wrong if files hadn't already
  been created.

# v3.1.1

- Fixed "insufficient permissions" check being completely wrong if files hadn't already
  been created.

# v3.1.0

- Fixed "insufficient permissions" error not printing a new line at the end.
- Added more detail to insufficient permission errors.

# v3.0.0

- certwrapper will now exit if it can't write to any of the required paths before attempting to
  obtain a certificate.
- Update to Go 1.17
- Support for building with only support for httpreq endpoints. This shaves about 30MB off the binary size. 

# v2.0.0

- Configuration of certwrapper can now be done using environment variables.

# v1.0.0

- Initial release

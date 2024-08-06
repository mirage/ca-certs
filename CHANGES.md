# v1.0.0 (2024-08-06)

* Use X509.Certificate.fold_decode_pem, available in x509 1.0.0 (#34 #35 @art-w
  @hannesm)
* Remove usage of cstruct, update to x509 1.0.0 and mirage-crypto 1.0.0 API
  (#32 @dinosaure @hannesm)
* Remove astring dependency (#26 @hannesm)

# v0.2.3 (2022-09-02)

* Respect the environment variable SSL_CERT_FILE as well (suggested in #22 by
  @Konubinix, fixed in #23 by @hannesm, ok'ed by @sternenseemann)
* Update tests for recent alpine releases (#24 @hannesm, likely fixes #21)

# v0.2.2 (2021-10-27)

* Filter trailing certificate (if the data does not contain
  "-----BEGIN CERTIFICATE-----", it won't be a certificate) (#19 @hannesm)
* Avoid deprecated functions from fmt (#19 @hannesm)
* Remove rresult dependency (#19 @hannesm)
* Update GitHub actions (#19 @hannesm)

# v0.2.1 (2021-04-22)

* Update to X.509 0.13.0 API (#18, @hannesm)
* Respect NIX_SSL_CERT_FILE environment variable to support NixOS builds
  (reported by @sternenseemann in #16, fix in #17 by @hannesm)

# v0.2.0 (2021-03-05)

* Add Windows support (#14, @emillon)

# v0.1.3 (2020-11-17)

* Allow some certificates to fail decoding (#11, reported by @mattpallissard
  in mirleft/ocaml-x509#137)

# v0.1.2 (2020-10-12)

* Revise API, avoid temporary file creation on macos

# v0.1.1 (2020-10-11)

* Revise test suite to not connect to the network (to please opam's sandbox),
  instead use hardcoded certificate chains.

# v0.1.0 (2020-10-09)

* Tested on macos, Debian GNU/Linux, Ubuntu, Gentoo, Alpine, CentOS/RHEL 7,
  OpenSUSE, FreeBSD, OpenBSD
* Initial release

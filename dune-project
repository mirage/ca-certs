(lang dune 2.0)
(name ca-certs)

(generate_opam_files true)
(source (github mirage/ca-certs))
(documentation "https://mirage.github.io/ca-certs/doc")
(license ISC)
(maintainers "Etienne Millon <me@emillon.org>")
(authors "Etienne Millon <me@emillon.org>, Hannes Mehnert <hannes@mehnert.org>")

(package
 (name ca-certs)
 (depends
  bos fpath ptime logs
  (digestif (>= 1.2.0))
  (mirage-crypto (>= 1.0.0))
  (x509 (>= 1.0.0))
  (ocaml (>= 4.13.0))
  (ohex (>= 0.2.0))
  (alcotest :with-test)
  (fmt (and :with-test (>= 0.8.7))))
 (conflicts (result (< 1.5)))
 (synopsis "Detect root CA certificates from the operating system")
 (description
   "\> TLS requires a set of root anchors (Certificate Authorities) to
   "\> authenticate servers. This library exposes this list so that it can be
   "\> registered with ocaml-tls.
 )
 ; tags are not included before (lang dune 2.0)
 ; so an opam template is necessary until then
 (tags (org:mirage)))

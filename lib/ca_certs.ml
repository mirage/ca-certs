(*
    "/etc/ssl/certs/ca-certificates.crt" (* Debian/Ubuntu/Gentoo etc.*);
    (* "/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6*)
    (* "/etc/ssl/ca-bundle.pem",                            // OpenSUSE*)
    (* "/etc/pki/tls/cacert.pem",                           // OpenELEC*)
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" (* CentOS/RHEL 7*);
      (* "/etc/ssl/cert.pem",                                 // Alpine Linux*)
   *)

let rec detect_list =
  let open Lwt in
  function
  | [] -> return_none
  | path :: paths ->
      Lwt_unix.file_exists path >>= fun exists ->
      if exists then return_some (`Ca_file path) else detect_list paths

let locations =
  [
    "/etc/ssl/certs/ca-certificates.crt";
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
  ]

let detect () = detect_list locations

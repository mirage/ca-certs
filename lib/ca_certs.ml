let rec detect_list =
  let open Lwt in
  function
  | [] -> return_none
  | path :: paths ->
      Lwt_unix.file_exists path >>= fun exists ->
      if exists then return_some (`Ca_file path) else detect_list paths

(* from https://golang.org/src/crypto/x509/root_linux.go *)
let locations =
  [
    (* Debian/Ubuntu/Gentoo etc. *)
    "/etc/ssl/certs/ca-certificates.crt";
    (* CentOS/RHEL 7 *)
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
    (* OpenSUSE *)
    "/etc/ssl/ca-bundle.pem";
  ]

let detect () = detect_list locations

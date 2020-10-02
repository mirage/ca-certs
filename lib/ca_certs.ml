let rec detect_list = function
  | [] -> Error (`Msg "no trust anchor file exists")
  | path :: paths -> (
      let path = Fpath.v path in
      match Bos.OS.Path.exists path with
      | Ok true -> Ok path
      | _ -> detect_list paths )

(* from https://golang.org/src/crypto/x509/root_linux.go *)
let linux_locations =
  [
    (* Debian/Ubuntu/Gentoo etc. *)
    "/etc/ssl/certs/ca-certificates.crt";
    (* CentOS/RHEL 7 *)
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";
    (* OpenSUSE *)
    "/etc/ssl/ca-bundle.pem";
  ]

(* from https://golang.org/src/crypto/x509/root_bsd.go *)
let openbsd_locations = [ (* OpenBSD *) "/etc/ssl/cert.pem" ]

let freebsd_locations =
  [ (* FreeBSD *) "/usr/local/share/certs/ca-root-nss.crt" ]

let ta_file_raw () =
  let open Rresult.R.Infix in
  if Sys.win32 then Error (`Msg "windows is not supported at the moment")
  else
    let cmd = Bos.Cmd.(v "uname" % "-s") in
    (Bos.OS.Cmd.(run_out cmd |> out_string |> success) >>= function
     | "FreeBSD" -> Ok freebsd_locations
     | "OpenBSD" -> Ok openbsd_locations
     | "Linux" -> Ok linux_locations
     | s -> Error (`Msg ("unknown system " ^ s)))
    >>= fun locs -> detect_list locs

let trust_anchor_filename () =
  let open Rresult.R.Infix in
  ta_file_raw () >>| Fpath.to_string

let trust_anchor ?hash_whitelist () =
  let open Rresult.R.Infix in
  ta_file_raw () >>= fun file ->
  Bos.OS.File.read file >>= fun data ->
  X509.Certificate.decode_pem_multiple (Cstruct.of_string data) >>| fun cas ->
  let time () = Some (Ptime_clock.now ()) in
  X509.Authenticator.chain_of_trust ?hash_whitelist ~time cas

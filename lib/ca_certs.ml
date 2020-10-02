let detect_one path =
  let path = Fpath.v path in
  match Bos.OS.Path.exists path with
  | Ok true -> Ok path
  | _ -> Error (`Msg "not found")

let rec detect_list = function
  | [] -> Error (`Msg "no trust anchor file exists")
  | path :: paths -> (
      match detect_one path with
      | Ok path -> Ok path
      | Error _ -> detect_list paths )

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
let openbsd_location = "/etc/ssl/cert.pem"

let freebsd_location = "/usr/local/share/certs/ca-root-nss.crt"

let macos_keychain_location =
  "/System/Library/Keychains/SystemRootCertificates.keychain"

let ta_file_raw () =
  let open Rresult.R.Infix in
  if Sys.win32 then Error (`Msg "windows is not supported at the moment")
  else
    let cmd = Bos.Cmd.(v "uname" % "-s") in
    Bos.OS.Cmd.(run_out cmd |> out_string |> success) >>= function
    | "FreeBSD" -> detect_one freebsd_location
    | "OpenBSD" -> detect_one openbsd_location
    | "Linux" -> detect_list linux_locations
    | "Darwin" ->
        let cmd =
          Bos.Cmd.(
            v "security" % "find-certificate" % "-a" % "-p"
            % macos_keychain_location)
        in
        let tmpfile = Fpath.v (Filename.temp_file "cacert" "pem") in
        Bos.OS.Cmd.(run_out cmd |> out_file tmpfile |> success) >>| fun () ->
        tmpfile
    | s -> Error (`Msg ("unknown system " ^ s))

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

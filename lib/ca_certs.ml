let src = Logs.Src.create "ca-certs" ~doc:"CA certificates"

module Log = (val Logs.src_log src : Logs.LOG)

let issue =
  {|Please report an issue at https://github.com/mirage/ca-certs, including:
- the output of uname -s
- the distribution you use
- the location of default trust anchors (if known)
|}

let detect_one path =
  let path' = Fpath.v path in
  match Bos.OS.Path.exists path' with
  | Ok true -> Bos.OS.File.read path'
  | _ ->
      Error
        (`Msg
          ("ca-certs: no trust anchor file found, looked into " ^ path ^ ".\n"
         ^ issue))

let detect_list paths =
  let rec one = function
    | [] ->
        Error
          (`Msg
            ("ca-certs: no trust anchor file found, looked into "
           ^ String.concat ", " paths ^ ".\n" ^ issue))
    | path :: paths -> (
        match detect_one path with Ok data -> Ok data | Error _ -> one paths)
  in
  one paths

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

external iter_on_anchors : (string -> unit) -> unit = "ca_certs_iter_on_anchors"

let get_anchors () =
  let der_list = ref [] in
  match iter_on_anchors (fun der_cert -> der_list := der_cert :: !der_list) with
  | () -> Ok !der_list
  | exception Failure msg -> Error (`Msg msg)

let ( let* ) = Result.bind

(** Load certificates from Windows' ["ROOT"] system certificate store.
    The C API returns a list of DER-encoded certificates. These are decoded and
    reencoded as a single PEM certificate. *)
let windows_trust_anchors () =
  let* anchors = get_anchors () in
  let cert_list =
    List.fold_left
      (fun acc cert ->
        match X509.Certificate.decode_der cert with
        | Ok cert -> cert :: acc
        | Error (`Msg msg) ->
            Log.debug (fun m -> m "Ignoring undecodable trust anchor: %s." msg);
            Log.debug (fun m ->
                m "Full certificate:@.%a" (Ohex.pp_hexdump ()) cert);
            acc)
      [] anchors
  in
  Ok (X509.Certificate.encode_pem_multiple cert_list)

let trust_anchors () =
  if Sys.win32 then windows_trust_anchors ()
  else
    (* NixOS is special and sets "NIX_SSL_CERT_FILE" as location during builds *)
    match
      (Sys.getenv_opt "SSL_CERT_FILE", Sys.getenv_opt "NIX_SSL_CERT_FILE")
    with
    | Some x, _ ->
        Log.debug (fun m -> m "using %s (from SSL_CERT_FILE)" x);
        detect_one x
    | _, Some x ->
        Log.debug (fun m -> m "using %s (from NIX_SSL_CERT_FILE)" x);
        detect_one x
    | None, None -> (
        let cmd = Bos.Cmd.(v "uname" % "-s") in
        let* os = Bos.OS.Cmd.(run_out cmd |> out_string |> success) in
        match os with
        | "FreeBSD" -> detect_one freebsd_location
        | "OpenBSD" -> detect_one openbsd_location
        | "Linux" -> detect_list linux_locations
        | "Darwin" ->
            let cmd =
              Bos.Cmd.(
                v "security" % "find-certificate" % "-a" % "-p"
                % macos_keychain_location)
            in
            Bos.OS.Cmd.(run_out cmd |> out_string |> success)
        | s -> Error (`Msg ("ca-certs: unknown system " ^ s ^ ".\n" ^ issue)))

let decode_pem_multiple data =
  X509.Certificate.fold_decode_pem_multiple
    (fun acc -> function
      | Ok t -> t :: acc
      | Error (`Msg msg) ->
          Log.debug (fun m -> m "Ignoring undecodable trust anchor: %s." msg);
          acc)
    [] data

let authenticator ?crls ?allowed_hashes () =
  let* data = trust_anchors () in
  let time () = Some (Ptime_clock.now ()) in
  let cas = decode_pem_multiple data in
  match cas with
  | [] -> Error (`Msg ("ca-certs: empty trust anchors.\n" ^ issue))
  | _ -> Ok (X509.Authenticator.chain_of_trust ?crls ?allowed_hashes ~time cas)

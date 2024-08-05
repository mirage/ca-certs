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
  match iter_on_anchors (fun der_cert ->
      Logs.debug (fun m -> m "cert: %a" (Ohex.pp_hexdump ()) der_cert);
      der_list := der_cert :: !der_list)
  with
  | () -> Ok !der_list
  | exception Failure msg -> Error (`Msg msg)

let ( let* ) = Result.bind

let rec map_m f l =
  match l with
  | [] -> Ok []
  | x :: xs ->
      let* y = f x in
      let* ys = map_m f xs in
      Ok (y :: ys)

(** Load certificates from Windows' ["ROOT"] system certificate store.
    The C API returns a list of DER-encoded certificates. These are decoded and
    reencoded as a single PEM certificate. *)
let windows_trust_anchors () =
  let* anchors = get_anchors () in
  Logs.info (fun m -> m "found %u anchors" (List.length anchors));
  let* cert_list = map_m X509.Certificate.decode_der anchors in
  Logs.info (fun m -> m "cert list is %u" (List.length cert_list));
  Ok (X509.Certificate.encode_pem_multiple cert_list)

let trust_anchors () =
  if Sys.win32 then windows_trust_anchors ()
  else
    (* NixOS is special and sets "NIX_SSL_CERT_FILE" as location during builds *)
    match
      (Sys.getenv_opt "SSL_CERT_FILE", Sys.getenv_opt "NIX_SSL_CERT_FILE")
    with
    | Some x, _ ->
        Log.info (fun m -> m "using %s (from SSL_CERT_FILE)" x);
        detect_one x
    | _, Some x ->
        Log.info (fun m -> m "using %s (from NIX_SSL_CERT_FILE)" x);
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

let authenticator ?crls ?allowed_hashes () =
  let* data = trust_anchors () in
  let time () = Some (Ptime_clock.now ()) in
  (* we cannot use decode_pem_multiple since this fails on the first
     undecodable certificate - while we'd like to stay operational, and ignore
     some certificates *)
  let d = "-----" in
  let new_cert = d ^ "BEGIN CERTIFICATE" ^ d
  and end_of_cert = d ^ "END CERTIFICATE" ^ d in
  let len_new = String.length new_cert
  and len_end = String.length end_of_cert in
  let lines = String.split_on_char '\n' data in
  let it, cas =
    List.fold_left
      (fun (acc, cas) line ->
        match acc with
        | None
          when String.length line >= len_new
               && String.(equal (sub line 0 len_new) new_cert) ->
            (Some [ line ], cas)
        | None ->
            Log.debug (fun m -> m "ignoring line %s" line);
            (None, cas)
        | Some lines
          when String.length line >= len_end
               && String.(equal (sub line 0 len_end) end_of_cert) -> (
            let data = String.concat "\n" (List.rev (line :: lines)) in
            match X509.Certificate.decode_pem data with
            | Ok ca -> (None, ca :: cas)
            | Error (`Msg msg) ->
                Log.warn (fun m -> m "Failed to decode a trust anchor %s." msg);
                Log.debug (fun m -> m "Full certificate:@.%s" data);
                (None, cas))
        | Some lines -> (Some (line :: lines), cas))
      (None, []) lines
  in
  (match it with
  | None -> ()
  | Some lines ->
      Log.debug (fun m ->
          m "ignoring leftover data: %s" (String.concat "\n" (List.rev lines))));
  let cas = List.rev cas in
  match cas with
  | [] -> Error (`Msg ("ca-certs: empty trust anchors.\n" ^ issue))
  | _ -> Ok (X509.Authenticator.chain_of_trust ?crls ?allowed_hashes ~time cas)

val trust_anchor_filename : unit -> (string, [> `Msg of string ]) result
(** Attempts to discover the trust anchor file on this host system. *)

val trust_anchor :
  ?hash_whitelist:Mirage_crypto.Hash.hash list ->
  unit ->
  (X509.Authenticator.t, [> `Msg of string ]) result
(** Detects root CAs in the operating system's trust store.
    Returns [Error `Msg msg] if detection did not succeed. *)

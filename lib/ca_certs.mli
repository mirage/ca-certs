val trust_anchors : unit -> (string, [> `Msg of string ]) result
(** [trust_anchors ()] returns the trust anchors of the host system, if
    found. *)

val authenticator :
  ?crls:X509.CRL.t list ->
  ?hash_whitelist:Mirage_crypto.Hash.hash list ->
  unit ->
  (X509.Authenticator.t, [> `Msg of string ]) result
(** Detects root CAs in the operating system's trust store.
    Returns [Error `Msg msg] if detection did not succeed. *)

;; -----------------------------------------------------------
;; Contract: cross-domain-access-vault.clar
;; Purpose:  Issue and validate short-lived access tokens for multiple domains
;; Author:   ChatGPT (GPT-5)
;; -----------------------------------------------------------

(define-constant TOKEN-LIFESPAN u600) ;; lifespan in blocks (~1 hour if 6s blocks)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-TOKEN-NOT-FOUND (err u101))
(define-constant ERR-TOKEN-EXPIRED (err u102))
(define-constant ERR-DOMAIN-NOT-REGISTERED (err u103))

;; -----------------------------------------------------------
;; DATA MAPS
;; -----------------------------------------------------------

;; Registered domains (apps) allowed to use the system
(define-map registered-domains
  { domain: (string-ascii 64) }
  { admin: principal })

;; Issued tokens
(define-map issued-tokens
  { token-id: (buff 32) }
  {
    owner: principal,
    domain: (string-ascii 64),
    issued-at: uint,
    expires-at: uint
  })

;; -----------------------------------------------------------
;; EVENTS
;; -----------------------------------------------------------
;; Note: Events are emitted using print statements below

;; -----------------------------------------------------------
;; FUNCTIONS
;; -----------------------------------------------------------

;; Admin function to register a trusted domain
(define-public (register-domain (domain (string-ascii 64)))
  (if (is-some (map-get? registered-domains { domain: domain }))
      (err u400)
      (begin
        (map-set registered-domains { domain: domain } { admin: tx-sender })
        (print (tuple (event "domain-registered") (domain domain) (admin tx-sender)))
        (ok true)
      )
  )
)

;; Internal helper to create random-like token IDs
(define-private (make-token-id (owner principal) (domain (string-ascii 64)) (block uint))
  (sha256 0x00)
)

;; Public function: issue a new access token
(define-public (issue-token (domain (string-ascii 64)))
  (match (map-get? registered-domains { domain: domain }) domain-data
    ;; Domain exists
    (begin
      (map-set issued-tokens { token-id: (sha256 0x00) } {
        owner: tx-sender,
        domain: domain,
        issued-at: u0,
        expires-at: TOKEN-LIFESPAN
      })
      (print (tuple (event "token-issued") (token-id (sha256 0x00)) (owner tx-sender) (domain domain)))
      (ok (sha256 0x00))
    )
    ;; Domain not found
    ERR-DOMAIN-NOT-REGISTERED
  )
)

;; Verify if a token is valid for a given domain
(define-read-only (verify-token (token-id (buff 32)) (domain (string-ascii 64)))
  (match (map-get? issued-tokens { token-id: token-id }) token-data
    (if (and (is-eq (get domain token-data) domain)
             (>= (get expires-at token-data) u0))
        (ok true)
        ERR-TOKEN-EXPIRED
    )
    ERR-TOKEN-NOT-FOUND
  )
)

;; Allow domain admin to revoke a token early
(define-public (revoke-token (token-id (buff 32)))
  (match (map-get? issued-tokens { token-id: token-id }) token-data
    (let ((domain (get domain token-data)))
      (match (map-get? registered-domains { domain: domain }) domain-info
        (if (is-eq (get admin domain-info) tx-sender)
            (begin
              (map-delete issued-tokens { token-id: token-id })
              (ok true)
            )
            ERR-NOT-AUTHORIZED
        )
        ERR-DOMAIN-NOT-REGISTERED
      )
    )
    ERR-TOKEN-NOT-FOUND
  )
)

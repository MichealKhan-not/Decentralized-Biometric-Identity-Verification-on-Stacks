;; biometric-verifier.clar

(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-HASH-LENGTH u101)
(define-constant ERR-INVALID-SALT u102)
(define-constant ERR-INVALID-EXPIRATION u103)
(define-constant ERR-INVALID-VERIFICATION-TYPE u104)
(define-constant ERR-INVALID-THRESHOLD u105)
(define-constant ERR-IDENTITY-ALREADY-VERIFIED u106)
(define-constant ERR-IDENTITY-NOT-FOUND u107)
(define-constant ERR-INVALID-TIMESTAMP u108)
(define-constant ERR-AUTHORITY-NOT-VERIFIED u109)
(define-constant ERR-INVALID-MIN-CONFIDENCE u110)
(define-constant ERR-INVALID-MAX-ATTEMPTS u111)
(define-constant ERR-VERIFICATION-EXPIRED u112)
(define-constant ERR-INVALID-UPDATE-PARAM u113)
(define-constant ERR-MAX-VERIFICATIONS-EXCEEDED u114)
(define-constant ERR-INVALID-BIOMETRIC-TYPE u115)
(define-constant ERR-INVALID-CONFIDENCE-SCORE u116)
(define-constant ERR-INVALID-GRACE-PERIOD u117)
(define-constant ERR-INVALID-LOCATION u118)
(define-constant ERR-INVALID-DEVICE-ID u119)
(define-constant ERR-INVALID-STATUS u120)
(define-constant ERR-ATTEMPTS-EXCEEDED u121)
(define-constant ERR-HASH-MISMATCH u122)
(define-constant ERR-SALT-MISMATCH u123)
(define-constant ERR-VERIFICATION-PENDING u124)
(define-constant ERR-VERIFICATION_FAILED u125)

(define-data-var next-verification-id uint u0)
(define-data-var max-verifications uint u10000)
(define-data-var verification-fee uint u500)
(define-data-var authority-contract (optional principal) none)

(define-map verifications
  uint
  {
    user: principal,
    biometric-hash: (string-ascii 64),
    salt: uint,
    expiration: uint,
    timestamp: uint,
    verifier: principal,
    biometric-type: (string-ascii 32),
    confidence-score: uint,
    grace-period: uint,
    location: (string-ascii 100),
    device-id: (string-ascii 64),
    status: bool,
    min-confidence: uint,
    max-attempts: uint,
    attempts: uint
  }
)

(define-map verifications-by-user
  principal
  uint)

(define-map verification-updates
  uint
  {
    update-hash: (string-ascii 64),
    update-salt: uint,
    update-expiration: uint,
    update-timestamp: uint,
    updater: principal
  }
)

(define-read-only (get-verification (id uint))
  (map-get? verifications id)
)

(define-read-only (get-verification-updates (id uint))
  (map-get? verification-updates id)
)

(define-read-only (is-user-verified (user principal))
  (is-some (map-get? verifications-by-user user))
)

(define-private (validate-hash (hash (string-ascii 64)))
  (if (is-eq (len hash) u64)
      (ok true)
      (err ERR-INVALID-HASH-LENGTH))
)

(define-private (validate-salt (salt uint))
  (if (> salt u0)
      (ok true)
      (err ERR-INVALID-SALT))
)

(define-private (validate-expiration (exp uint))
  (if (> exp block-height)
      (ok true)
      (err ERR-INVALID-EXPIRATION))
)

(define-private (validate-biometric-type (type (string-ascii 32)))
  (if (or (is-eq type "fingerprint") (is-eq type "facial") (is-eq type "iris"))
      (ok true)
      (err ERR-INVALID-BIOMETRIC-TYPE))
)

(define-private (validate-confidence-score (score uint))
  (if (and (>= score u0) (<= score u100))
      (ok true)
      (err ERR-INVALID-CONFIDENCE-SCORE))
)

(define-private (validate-grace-period (period uint))
  (if (<= period u30)
      (ok true)
      (err ERR-INVALID-GRACE-PERIOD))
)

(define-private (validate-location (loc (string-ascii 100)))
  (if (<= (len loc) u100)
      (ok true)
      (err ERR-INVALID-LOCATION))
)

(define-private (validate-device-id (id (string-ascii 64)))
  (if (<= (len id) u64)
      (ok true)
      (err ERR-INVALID-DEVICE-ID))
)

(define-private (validate-min-confidence (min uint))
  (if (and (>= min u0) (<= min u100))
      (ok true)
      (err ERR-INVALID-MIN-CONFIDENCE))
)

(define-private (validate-max-attempts (max uint))
  (if (> max u0)
      (ok true)
      (err ERR-INVALID-MAX-ATTEMPTS))
)

(define-private (validate-principal (p principal))
  (if (not (is-eq p 'SP000000000000000000002Q6VF78))
      (ok true)
      (err ERR-NOT-AUTHORIZED))
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (try! (validate-principal contract-principal))
    (asserts! (is-none (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-max-verifications (new-max uint))
  (begin
    (asserts! (> new-max u0) (err ERR-INVALID_UPDATE-PARAM))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set max-verifications new-max)
    (ok true)
  )
)

(define-public (set-verification-fee (new-fee uint))
  (begin
    (asserts! (>= new-fee u0) (err ERR-INVALID_UPDATE-PARAM))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-VERIFIED))
    (var-set verification-fee new-fee)
    (ok true)
  )
)

(define-public (initiate-verification
  (user principal)
  (biometric-hash (string-ascii 64))
  (salt uint)
  (expiration uint)
  (biometric-type (string-ascii 32))
  (confidence-score uint)
  (grace-period uint)
  (location (string-ascii 100))
  (device-id (string-ascii 64))
  (min-confidence uint)
  (max-attempts uint)
)
  (let (
        (next-id (var-get next-verification-id))
        (current-max (var-get max-verifications))
        (authority (var-get authority-contract))
      )
    (asserts! (< next-id current-max) (err ERR-MAX-VERIFICATIONS-EXCEEDED))
    (try! (validate-hash biometric-hash))
    (try! (validate-salt salt))
    (try! (validate-expiration expiration))
    (try! (validate-biometric-type biometric-type))
    (try! (validate-confidence-score confidence-score))
    (try! (validate-grace-period grace-period))
    (try! (validate-location location))
    (try! (validate-device-id device-id))
    (try! (validate-min-confidence min-confidence))
    (try! (validate-max-attempts max-attempts))
    (asserts! (is-none (map-get? verifications-by-user user)) (err ERR-IDENTITY-ALREADY-VERIFIED))
    (let ((authority-recipient (unwrap! authority (err ERR-AUTHORITY-NOT-VERIFIED))))
      (try! (stx-transfer? (var-get verification-fee) tx-sender authority-recipient))
    )
    (map-set verifications next-id
      {
        user: user,
        biometric-hash: biometric-hash,
        salt: salt,
        expiration: expiration,
        timestamp: block-height,
        verifier: tx-sender,
        biometric-type: biometric-type,
        confidence-score: confidence-score,
        grace-period: grace-period,
        location: location,
        device-id: device-id,
        status: false,
        min-confidence: min-confidence,
        max-attempts: max-attempts,
        attempts: u0
      }
    )
    (map-set verifications-by-user user next-id)
    (var-set next-verification-id (+ next-id u1))
    (print { event: "verification-initiated", id: next-id })
    (ok next-id)
  )
)

(define-public (perform-verification
  (id uint)
  (submitted-hash (string-ascii 64))
  (submitted-salt uint)
  (submitted-confidence uint)
)
  (let ((verification (map-get? verifications id)))
    (match verification
      v
        (begin
          (asserts! (is-eq (get verifier v) tx-sender) (err ERR-NOT-AUTHORIZED))
          (asserts! (<= block-height (get expiration v)) (err ERR-VERIFICATION-EXPIRED))
          (asserts! (< (get attempts v) (get max-attempts v)) (err ERR-ATTEMPTS-EXCEEDED))
          (try! (validate-hash submitted-hash))
          (try! (validate-salt submitted-salt))
          (try! (validate-confidence-score submitted-confidence))
          (asserts! (is-eq submitted-hash (get biometric-hash v)) (err ERR-HASH-MISMATCH))
          (asserts! (is-eq submitted-salt (get salt v)) (err ERR-SALT-MISMATCH))
          (asserts! (>= submitted-confidence (get min-confidence v)) (err ERR-INVALID-CONFIDENCE-SCORE))
          (map-set verifications id
            (merge v {
              status: true,
              timestamp: block-height,
              confidence-score: submitted-confidence,
              attempts: (+ (get attempts v) u1)
            })
          )
          (print { event: "verification-performed", id: id })
          (ok true)
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)

(define-public (update-verification
  (id uint)
  (update-hash (string-ascii 64))
  (update-salt uint)
  (update-expiration uint)
)
  (let ((verification (map-get? verifications id)))
    (match verification
      v
        (begin
          (asserts! (is-eq (get verifier v) tx-sender) (err ERR-NOT-AUTHORIZED))
          (try! (validate-hash update-hash))
          (try! (validate-salt update-salt))
          (try! (validate-expiration update-expiration))
          (map-set verifications id
            (merge v {
              biometric-hash: update-hash,
              salt: update-salt,
              expiration: update-expiration,
              timestamp: block-height
            })
          )
          (map-set verification-updates id
            {
              update-hash: update-hash,
              update-salt: update-salt,
              update-expiration: update-expiration,
              update-timestamp: block-height,
              updater: tx-sender
            }
          )
          (print { event: "verification-updated", id: id })
          (ok true)
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)

(define-public (revoke-verification (id uint))
  (let ((verification (map-get? verifications id)))
    (match verification
      v
        (begin
          (asserts! (or (is-eq (get user v) tx-sender) (is-eq (get verifier v) tx-sender)) (err ERR-NOT-AUTHORIZED))
          (map-delete verifications id)
          (map-delete verifications-by-user (get user v))
          (map-delete verification-updates id)
          (print { event: "verification-revoked", id: id })
          (ok true)
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)

(define-public (get-verification-count)
  (ok (var-get next-verification-id))
)

(define-public (check-user-verification (user principal))
  (ok (is-user-verified user))
)

(define-public (increment-attempt (id uint))
  (let ((verification (map-get? verifications id)))
    (match verification
      v
        (begin
          (asserts! (is-eq (get verifier v) tx-sender) (err ERR-NOT-AUTHORIZED))
          (asserts! (< (get attempts v) (get max-attempts v)) (err ERR-ATTEMPTS-EXCEEDED))
          (map-set verifications id
            (merge v { attempts: (+ (get attempts v) u1) })
          )
          (ok true)
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)

(define-public (reset-attempts (id uint))
  (let ((verification (map-get? verifications id)))
    (match verification
      v
        (begin
          (asserts! (is-eq (get verifier v) tx-sender) (err ERR-NOT-AUTHORIZED))
          (map-set verifications id
            (merge v { attempts: u0 })
          )
          (ok true)
        )
      (err ERR-IDENTITY-NOT-FOUND)
    )
  )
)
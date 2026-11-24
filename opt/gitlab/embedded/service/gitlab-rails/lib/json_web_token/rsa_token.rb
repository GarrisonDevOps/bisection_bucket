# frozen_string_literal: true

module JSONWebToken
  class RSAToken < Token
    ALGORITHM = 'RS256'

    CachedKey = Struct.new(:key, :mtime)
    KEYS = Concurrent::Map.new

    attr_reader :key_file

    def initialize(key_file)
      super()
      @key_file = key_file
    end

    def encoded
      self.class.encode(payload, key, kid)
    end

    def self.encode(payload, key, kid)
      headers = { kid: kid, typ: 'JWT' }
      JWT.encode(payload, key, ALGORITHM, headers)
    end

    def self.decode(token, key, verify_expiration: true)
      JWT.decode(
        token,
        key,
        true,
        {
          algorithm: ALGORITHM,
          verify_expiration: verify_expiration
        }
      )
    end

    # Parsing the PEM dominates the cost of signing, and the registry auth
    # endpoint signs two tokens per request. Re-read when the file changes.
    def self.cached_key(key_file)
      mtime = File.mtime(key_file)
      cached = KEYS[key_file]
      return cached.key if cached&.mtime == mtime

      key = OpenSSL::PKey::RSA.new(File.read(key_file))
      KEYS[key_file] = CachedKey.new(key, mtime)
      key
    end

    private

    def key
      @key ||= self.class.cached_key(key_file)
    end

    def public_key
      key.public_key
    end

    def kid
      # calculate sha256 from DER encoded ASN1
      kid = Digest::SHA256.digest(public_key.to_der)

      # we encode only 30 bytes with base32
      kid = Base32.encode(kid[0..29])

      # insert colon every 4 characters
      kid.scan(/.{4}/).join(':')
    end
  end
end

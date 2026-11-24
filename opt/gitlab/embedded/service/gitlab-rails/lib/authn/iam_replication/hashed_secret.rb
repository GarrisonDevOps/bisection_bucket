# frozen_string_literal: true

module Authn
  module IamReplication
    # Safety measure: a value that is not a supported digest is sent as its SHA-512 digest.
    module HashedSecret
      SHA512_HEX_DIGEST = /\A[0-9a-f]{128}\z/
      PBKDF2_PREFIX = '$pbkdf2-sha512$'

      def self.of(value)
        return value if SHA512_HEX_DIGEST.match?(value) || value.start_with?(PBKDF2_PREFIX)

        ::Gitlab::DoorkeeperSecretStoring::Sha512Hash.transform_secret(value)
      end
    end
  end
end

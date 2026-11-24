# frozen_string_literal: true

module Gitlab
  module Encryption
    module DbKeyBaseRotation
      # An encrypted token field (`add_authentication_token_field ..., encrypted:`), re-encrypted
      # from its stored `<field>_encrypted` column.
      class TokenColumn
        # @param token_field [Symbol] the token field, for example `:runners_token`
        def initialize(token_field)
          @column = "#{token_field}_encrypted"
        end

        # @return [Array<String>] the stored column
        def columns
          [column]
        end

        # @return [Hash] the options that must match for two declarations to share a column
        def definition
          { column: column }
        end

        # Re-encrypts the stored token with the current key when an older key encrypted it.
        #
        # @param values [Hash{String => String, nil}] the stored values of {#columns}
        # @return [Hash{String => String}, nil] the new value of the column, or nil when the token is
        #   empty or already on the current key
        # @raise [OpenSSL::Cipher::CipherError] when no key decrypts the token
        def reencrypt(values)
          stored = values[column]
          return if stored.blank?

          token = Authn::TokenField::EncryptionHelper.decrypt_token(stored)
          raise OpenSSL::Cipher::CipherError, "#{column} decrypts to an empty token" if token.blank?
          return if current?(stored, token)

          new_value = Authn::TokenField::EncryptionHelper.encrypt_token(token)
          verify!(new_value, token)

          { column => new_value }
        end

        private

        attr_reader :column

        # Tokens are encrypted deterministically, so a value on the current key is one of the
        # values the current key gives: the dynamic-nonce format or the legacy static IV.
        def current?(stored, token)
          stored == Authn::TokenField::EncryptionHelper.encrypt_token(token) ||
            stored == Gitlab::CryptoHelper.aes256_gcm_encrypt(token)
        end

        def verify!(new_value, token)
          return if Authn::TokenField::EncryptionHelper.decrypt_token(new_value) == token

          raise OpenSSL::Cipher::CipherError, "#{column} doesn't decrypt after re-encryption"
        end
      end
    end
  end
end

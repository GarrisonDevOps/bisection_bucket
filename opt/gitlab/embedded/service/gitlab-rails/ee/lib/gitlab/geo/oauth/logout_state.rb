# frozen_string_literal: true

module Gitlab
  module Geo
    module Oauth
      class LogoutState
        include ::Gitlab::Utils::StrongMemoize

        def self.from_state(state)
          salt, tag, encrypted, return_to = state.to_s.split(':', 4)
          self.new(salt: salt, tag: tag, token: encrypted, return_to: return_to)
        end

        def initialize(token:, salt: nil, tag: nil, return_to: nil)
          @token = token
          @salt = decode_base64(salt)
          @tag = decode_base64(tag)
          @return_to_location = Gitlab::ReturnToLocation.new(return_to)
        end

        def decode
          return unless salt && tag && token
          return unless tag.bytesize == 16

          encrypted = decode_base64(token)
          return unless encrypted

          # Current key first, so states encrypted before a db_key_base rotation still decode
          decryption_keys.lazy.filter_map { |key| decrypt_with(encrypted, key) }.first
        rescue ArgumentError
          nil
        end

        def encode
          return unless token

          encrypted = encrypt.update(token) + encrypt.final
          salt_base64 = encode_base64(salt)
          auth_tag_base64 = encode_base64(encrypt.auth_tag)
          encrypted_base64 = encode_base64(encrypted)

          "#{salt_base64}:#{auth_tag_base64}:#{encrypted_base64}:#{return_to}"
        rescue ArgumentError, OpenSSL::OpenSSLError
          nil
        end

        def return_to
          return_to_location.full_path
        end

        private

        attr_reader :token, :salt, :tag, :return_to_location

        def encrypt
          strong_memoize(:encrypt) do
            with_cipher(&:encrypt)
          end
        end

        def decrypt_with(encrypted, key)
          cipher = with_cipher(tag, key: key, &:decrypt)
          cipher.update(encrypted) + cipher.final
        rescue OpenSSL::OpenSSLError
          nil
        end

        def decryption_keys
          ::Gitlab::Encryption::KeyProvider[:db_key_base_truncated].decryption_keys_current_first.map(&:secret)
        end

        def with_cipher(auth_tag = nil, key: nil)
          cipher = OpenSSL::Cipher.new('AES-256-GCM')

          yield cipher

          cipher.key = key || ::Gitlab::Encryption::KeyProvider[:db_key_base_truncated].encryption_key.secret
          cipher.iv = @salt ||= cipher.random_iv
          cipher.auth_tag = auth_tag if auth_tag
          cipher.auth_data = return_to.to_s
          cipher
        end

        def encode_base64(value)
          Base64.urlsafe_encode64(value)
        end

        def decode_base64(value)
          Base64.urlsafe_decode64(value)
        rescue ArgumentError, NoMethodError
          nil
        end
      end
    end
  end
end

# frozen_string_literal: true

module CloudConnector
  class Keys < ApplicationRecord
    self.table_name = 'cloud_connector_keys'

    encrypts :secret_key, previous: { key_provider: ActiveRecord::Encryption::EnvelopeEncryptionKeyProvider.new }
    validates :secret_key, rsa_key: true, allow_nil: true

    scope :valid, -> { where.not(secret_key: nil) }
    scope :ordered_by_date, -> { valid.order(created_at: :asc) }

    class << self
      def current
        ordered_by_date.first
      end

      def all_as_pem
        valid.map(&:secret_key)
      end

      def create_new_key!
        create!(secret_key: new_private_key.to_pem)
      end

      def rotate!
        keys = ordered_by_date
        key_count = keys.count

        raise "Key rotation requires exactly 2 keys, found #{key_count}" if key_count != 2

        current_key, next_key = *keys

        transaction do
          current_key_data = current_key.secret_key
          current_key.update!(secret_key: next_key.secret_key)
          next_key.update!(secret_key: current_key_data)
        end
      end

      def trim!
        raise 'Refusing to remove single key, as it is in use' if valid.count == 1

        ordered_by_date.last&.destroy
      end

      private

      def new_private_key
        OpenSSL::PKey::RSA.new(2048)
      end
    end

    def truncated_pem
      secret_key&.truncate(90)
    end

    def to_jwk
      return unless rsa_key_pair

      @jwk ||= ::JWT::JWK.new(rsa_key_pair, kid_generator: ::JWT::JWK::Thumbprint)
    end

    def public_key
      return unless rsa_key_pair

      @public_key ||= rsa_key_pair.public_key
    end

    def rsa_key_pair
      return unless secret_key

      @rsa_key_pair ||= OpenSSL::PKey::RSA.new(secret_key)
    end

    def decode_token(encoded_token)
      JWT.decode(encoded_token, public_key, true, algorithm: Gitlab::CloudConnector::JsonWebToken::SIGNING_ALGORITHM)
    end
  end
end

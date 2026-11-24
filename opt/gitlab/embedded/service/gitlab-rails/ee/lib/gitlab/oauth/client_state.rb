# frozen_string_literal: true

module Gitlab
  module Oauth
    # Encodes arbitrary data into a tamper-proof OAuth state parameter.
    #
    # The state string format is: `<salt>:<JWT>:<return_to>`
    # Extra data fields are embedded in the JWT payload and accessed via `[]`.
    #
    # @example Usage
    #   state = Gitlab::Oauth::ClientState.new(return_to: '/dashboard', data: { mcp_server_id: 42 })
    #   encoded = state.encode
    #
    #   state = Gitlab::Oauth::ClientState.from_state(encoded)
    #   state.valid?           # => true
    #   state.return_to        # => '/dashboard'
    #   state[:mcp_server_id]  # => '42'
    #
    class ClientState
      attr_reader :return_to

      def self.from_state(state)
        salt, token, return_to = state.to_s.split(':', 3)
        new(salt: salt, token: token, return_to: return_to)
      end

      def initialize(return_to:, data: {}, salt: nil, token: nil)
        @return_to = Gitlab::ReturnToLocation.new(return_to).full_path
        @data = data.transform_keys(&:to_s)
        @salt = salt
        @token = token
      end

      def encode
        "#{salt}:#{hmac_token}:#{return_to}"
      end

      def valid?
        return false unless salt.present? && token.present?

        decoded = JSONWebToken::HMACToken.decode(token, key).first
        decoded_data = decoded.fetch('data', {})

        secure_compare(decoded_data['return_to'], return_to.to_s) &&
          data.all? { |k, v| secure_compare(decoded_data[k].to_s, v.to_s) }
      rescue JWT::DecodeError
        false
      end

      def [](key)
        decoded_data[key.to_s]
      end

      private

      attr_reader :token, :data

      def expiration_time
        1.minute
      end

      def hmac_token
        hmac_token = JSONWebToken::HMACToken.new(key)
        hmac_token.expire_time = Time.current + expiration_time
        hmac_token[:data] = data.merge('return_to' => return_to.to_s)
        hmac_token.encoded
      end

      def key
        ActiveSupport::KeyGenerator
          .new(Gitlab::Application.credentials.secret_key_base)
          .generate_key(salt)
      end

      def salt
        @salt ||= SecureRandom.hex(8)
      end

      def decoded_data
        return {} unless token.present? && salt.present?

        JSONWebToken::HMACToken.decode(token, key).first.fetch('data', {})
      rescue JWT::DecodeError
        {}
      end

      def secure_compare(left, right)
        ActiveSupport::SecurityUtils.secure_compare(left.to_s, right.to_s)
      end
    end
  end
end

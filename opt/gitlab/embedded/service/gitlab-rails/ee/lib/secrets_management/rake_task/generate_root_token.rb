# frozen_string_literal: true

module SecretsManagement
  module RakeTask
    # Generates an OpenBao root token from the privileged GitLab JWT plus the recovery key.
    class GenerateRootToken
      DecodeError = Class.new(StandardError)

      CLIENT_ERRORS = [
        SecretsManagerClient::ApiError,
        SecretsManagerClient::AuthenticationError,
        SecretsManagerClient::ConnectionError,
        SecretsManagerClient::ServiceUnavailableError,
        DecodeError
      ].freeze

      def execute
        unless confirmed?("WARNING: This will generate an OpenBao root token and display it in plaintext. " \
          "Continue? [y/N]: ")
          puts "Aborted."
          return
        end

        return unless ready_to_start?

        recovery_key = read_recovery_key
        if recovery_key.empty?
          puts "\nNo recovery key entered. Aborted."
          return
        end

        root_token = generate(recovery_key)
        return unless root_token

        puts "\nRoot token (store securely — do not log or share outside a secure channel):"
        puts root_token
        puts "\nThis token does not expire. Revoke it as soon as you finish the privileged operations."
      rescue *CLIENT_ERRORS => e
        Gitlab::ErrorTracking.track_and_raise_exception(e)
      end

      private

      def ready_to_start?
        status = client.generate_root_token_status["data"]

        if status["required"].to_i == 0
          puts "OpenBao has no recovery key. Run recovery_key:store or recovery_key:fetch first."
          return false
        end

        return true unless status["started"]

        unless confirmed?("A root token generation is already in progress in OpenBao. " \
          "Cancel it and start a new one? [y/N]: ")
          puts "Aborted."
          return false
        end

        client.cancel_generate_root_token
        true
      end

      def read_recovery_key
        stored_key = RecoveryKey.active.take&.key # rubocop:disable CodeReuse/ActiveRecord -- rake task lookup, at most one active key
        if stored_key
          puts "Using the recovery key stored in the GitLab database."
          return stored_key
        end

        Gitlab::TaskHelpers.prompt_for_password('Enter the recovery key: ').to_s.strip
      end

      def generate(recovery_key)
        attempt_client = client
        attempt = attempt_client.init_generate_root_token["data"]
        result = attempt_client.update_generate_root_token(key: recovery_key, nonce: attempt["nonce"])["data"]

        unless result["complete"]
          puts "OpenBao did not complete the root token generation " \
            "(progress #{result['progress']} of #{result['required']})."
          return
        end

        decode_root_token(result["encoded_token"], attempt["otp"])
      ensure
        cancel_attempt(attempt_client) if attempt && !result&.dig("complete")
      end

      # OpenBao returns the token XOR-ed with the OTP, base64-encoded without padding.
      def decode_root_token(encoded_token, otp)
        token_bytes = Base64.urlsafe_decode64(encoded_token)
        raise DecodeError, "encoded token and OTP lengths differ" unless token_bytes.bytesize == otp.bytesize

        token_bytes.bytes.zip(otp.bytes).map { |token_byte, otp_byte| token_byte ^ otp_byte }.pack("C*")
      rescue ArgumentError
        raise DecodeError, "encoded token is not valid base64"
      end

      def cancel_attempt(attempt_client)
        attempt_client.cancel_generate_root_token
      rescue *CLIENT_ERRORS
        puts "Could not cancel the root token generation attempt in OpenBao. Rerun this task to cancel it."
      end

      def confirmed?(message)
        Gitlab::TaskHelpers.prompt(message).casecmp('y') == 0
      end

      # A fresh JWT per client: the privileged JWT expires 30 seconds after signing, and
      # the operator may spend longer than that at the prompts.
      def client
        SecretsManagerClient.new(jwt: GlobalSecretsManagerJwt.new.encoded)
      end
    end
  end
end

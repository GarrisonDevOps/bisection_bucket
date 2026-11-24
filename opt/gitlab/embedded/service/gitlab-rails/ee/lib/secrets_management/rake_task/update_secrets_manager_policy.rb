# frozen_string_literal: true

module SecretsManagement
  module RakeTask
    # Replaces the OpenBao policy behind the privileged GitLab JWT with secrets_manager_policy.hcl.
    # The restricted policy cannot write itself, so once it is applied, updates need a root token.
    class UpdateSecretsManagerPolicy
      POLICY_NAME = 'secrets_manager'
      POLICY_FILE = Rails.root.join('ee/lib/secrets_management/secrets_manager_policy.hcl')
      # sys/generate-root-token only exists from 2.6.0, and without it there is no way back.
      MINIMUM_SERVER_VERSION = Gitlab::VersionInfo.new(2, 6, 0)

      CLIENT_ERRORS = [
        SecretsManagerClient::ApiError,
        SecretsManagerClient::AuthenticationError,
        SecretsManagerClient::ConnectionError,
        SecretsManagerClient::ServiceUnavailableError
      ].freeze

      def initialize(dry_run: true)
        @dry_run = dry_run
      end

      def execute
        check_server_version!

        current_policy = client.read_policy_text(POLICY_NAME)
        if normalize(current_policy) == normalize(new_policy)
          puts "The #{POLICY_NAME} policy is already up to date. Nothing to do."
          return
        end

        puts "Current #{POLICY_NAME} policy:\n#{current_policy}\n"
        puts "New #{POLICY_NAME} policy:\n#{new_policy}\n"

        check_recovery_key!

        if dry_run
          puts "Dry run, nothing was written. Rerun with DRY_RUN=false to apply the new policy."
          return
        end

        write_new_policy
        verify_new_policy
        warn_to_revoke_root_token if root_token_used
      rescue *CLIENT_ERRORS => e
        Gitlab::ErrorTracking.track_and_raise_exception(e)
      end

      private

      attr_reader :dry_run, :root_token_used

      def check_server_version!
        version = client.server_version
        parsed_version = Gitlab::VersionInfo.parse(version)
        return if parsed_version.valid? && parsed_version >= MINIMUM_SERVER_VERSION

        abort "ERROR: OpenBao #{version.presence || 'version unknown'} is not supported. " \
          "Upgrade OpenBao to #{MINIMUM_SERVER_VERSION} or later first."
      end

      def check_recovery_key!
        if client.generate_root_token_status.dig("data", "required").to_i == 0
          no_recovery_key!
        elsif !RecoveryKey.active.exists?
          confirm_recovery_key_held!
        end
      end

      def no_recovery_key!
        message = "OpenBao has no recovery key. Store one with recovery_key:store first, so you have a " \
          "backed-up credential to generate a root token and change the #{POLICY_NAME} policy later."

        if dry_run
          puts "WARNING: #{message} A real run refuses until a recovery key exists.\n"
        else
          abort "ERROR: #{message}"
        end
      end

      # some installs keep the recovery key outside the GitLab database
      def confirm_recovery_key_held!
        message = "The GitLab database has no recovery key, so you need the OpenBao recovery key " \
          "from wherever it is kept to undo this change."

        if dry_run
          puts "NOTE: #{message} A real run asks you to confirm you have it.\n"
          return
        end

        return if confirmed?("#{message} Do you have it? [y/N]: ")

        abort "Aborted. Nothing was written."
      end

      def confirmed?(message)
        Gitlab::TaskHelpers.prompt(message).casecmp('y') == 0
      end

      def write_new_policy
        client.write_policy_text(POLICY_NAME, new_policy)
      rescue SecretsManagerClient::ApiError => e
        raise unless permission_denied?(e)

        write_new_policy_with_root_token
      end

      def write_new_policy_with_root_token
        puts "OpenBao denied the write. The current #{POLICY_NAME} policy does not allow changing itself, " \
          "so this update needs a root token. Generate one with root_token:generate, and revoke it when " \
          "this task finishes, because root tokens do not expire."
        root_token = Gitlab::TaskHelpers.prompt_for_password('Enter the root token: ').to_s.strip
        abort "No root token entered. Nothing was written." if root_token.empty?

        client.write_policy_text(POLICY_NAME, new_policy, token: root_token)
        @root_token_used = true
      rescue SecretsManagerClient::ApiError => e
        raise unless permission_denied?(e)

        abort "ERROR: OpenBao denied the write with this root token. Nothing was written."
      end

      def warn_to_revoke_root_token
        puts "WARNING: Root tokens do not expire. If you do not need this root token for more maintenance, " \
          "revoke it now with `bao token revoke -self`."
      end

      def permission_denied?(error)
        error.message.include?('permission denied')
      end

      def verify_new_policy
        if normalize(client.read_policy_text(POLICY_NAME)) == normalize(new_policy)
          puts "Applied the new #{POLICY_NAME} policy."
          return
        end

        abort "ERROR: the #{POLICY_NAME} policy read back from OpenBao does not match #{POLICY_FILE}."
      end

      # a copy with other comments or spacing still counts as applied
      def normalize(policy)
        policy.to_s.gsub(/#.*$/, '').gsub(/\s+/, '')
      end

      def new_policy
        @new_policy ||= File.read(POLICY_FILE)
      end

      # A fresh JWT per client: the privileged JWT expires 30 seconds after signing.
      def client
        SecretsManagerClient.new(jwt: GlobalSecretsManagerJwt.new.encoded)
      end
    end
  end
end

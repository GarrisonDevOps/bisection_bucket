# frozen_string_literal: true

namespace :cloud_connector do
  namespace :keys do
    desc 'GitLab | Cloud Connector | List private keys in PEM format'
    task :list, [:truncate] => :environment do |_, args|
      truncate_keys = Gitlab::Utils.to_boolean(args[:truncate], default: true)
      keys = truncate_keys ? CloudConnector::Keys.valid.map(&:truncated_pem) : CloudConnector::Keys.all_as_pem

      puts <<~TXT.strip
      ================================================================================
      #{keys.any? ? keys.join("\n") : 'No keys found.'}
      ================================================================================
      TXT
    rescue StandardError => e
      exit_with_message(e.message)
    end

    desc 'GitLab | Cloud Connector | Create and store a new private key'
    task create: :environment do
      key = CloudConnector::Keys.create_new_key!

      puts <<~TXT.strip
      ================================================================================
      Key created: #{key.truncated_pem}

      This key will now be published via /oauth/discovery/keys.

      If an older key existed prior to creation, run
      `bundle exec rake cloud_connector:keys:rotate` to use it for signing tokens.
      ================================================================================
      TXT
    rescue StandardError => e
      exit_with_message(e.message)
    end

    desc 'GitLab | Cloud Connector | Performs key rotation by swapping two keys'
    task rotate: :environment do
      CloudConnector::Keys.rotate!

      puts <<~TXT.strip
      ================================================================================
      Keys swapped successfully.

      Run this task again to revert to using the previous key.

      If the key that is now used to sign tokens should remain in use, run
      `bundle exec rake cloud_connector:keys:trim` to remove the old key.
      ================================================================================
      TXT
    rescue StandardError => e
      exit_with_message(e.message)
    end

    desc 'GitLab | Cloud Connector | Removes the newest key'
    task trim: :environment do
      key = CloudConnector::Keys.trim!

      puts <<~TXT.strip
      ================================================================================
      Key removed: #{key.truncated_pem}
      ================================================================================
      TXT
    rescue StandardError => e
      exit_with_message(e.message)
    end

    private

    def exit_with_message(message)
      puts <<~TXT.strip
      ================================================================================
      ERROR: #{message}
      ================================================================================
      TXT

      exit(1)
    end
  end
end

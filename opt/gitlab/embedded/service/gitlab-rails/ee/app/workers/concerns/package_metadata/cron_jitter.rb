# frozen_string_literal: true

module PackageMetadata # rubocop:disable Gitlab/BoundedContexts -- Existing context
  # Spreads the PDS calls of the sync workers across the self-managed fleet,
  # which all fire the same cron on the same tick.
  module CronJitter
    extend ActiveSupport::Concern

    MAX_JITTER = 5.minutes

    private

    # .com and staging are a single instance, so there is no fleet to spread.
    def apply_jitter?
      # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- deployment-topology gate, both branches covered by specs
      !::Gitlab.com?
      # rubocop:enable Gitlab/AvoidGitlabInstanceChecks
    end

    # Seeding with the class name keeps workers that share a cron schedule
    # from landing on the same offset.
    def jitter_offset
      seed = "#{::Gitlab::CurrentSettings.uuid}:#{self.class.name}"

      Digest::SHA256.hexdigest(seed).to_i(16) % MAX_JITTER.to_i
    end
  end
end

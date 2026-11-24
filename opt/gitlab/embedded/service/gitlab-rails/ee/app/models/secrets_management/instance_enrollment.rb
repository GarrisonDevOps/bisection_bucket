# frozen_string_literal: true

module SecretsManagement
  class InstanceEnrollment
    SETTINGS_REQUEST_STORE_KEY = :secrets_manager_instance_enrollment_settings
    SETTINGS_COLUMNS = %i[
      secrets_manager_instance_enrolled
      secrets_manager_instance_beta_enrolled
      secrets_manager_instance_add_on_requested_at
    ].freeze

    def self.enrolled?
      settings.secrets_manager_instance_enrolled
    end

    # Secrets Manager on self-managed is beta only, so all enrolled instances are in beta.
    # When GA launches, add a secrets_manager_instance_ga_enrolled setting and also check !ga_enrolled?.
    def self.beta?
      enrolled?
    end

    # Self-managed counterpart of `NamespaceEnrollment.beta_enrolled?`. The marker
    # is written at enrollment time (`InstanceEnrollmentService#beta_enrollment?`)
    # and backfilled for earlier enrollments, so it never depends on live rows.
    def self.beta_enrolled?
      beta? && settings.secrets_manager_instance_beta_enrolled
    end

    # Add-on intent: an administrator enabled paid Secrets Manager for the
    # instance without a trial. Distinct from plain enrollment, which the beta
    # opt-in also sets. Mirrors NamespaceEnrollment.add_on_requested?: not tied
    # to enrolled?, so an opt-out pauses the add-on and the state stays paid.
    def self.add_on_requested?
      settings.secrets_manager_instance_add_on_requested_at.present?
    end

    # Writes the stamp only while it is still empty, so of two concurrent
    # enables exactly one gets `true` and claims the first conversion. Callers
    # must expire the entitlement cache afterwards.
    def self.stamp_add_on_intent!
      current_settings = ::Gitlab::CurrentSettings.current_application_settings
      now = Time.current

      updated = ::ApplicationSetting
        .where(id: current_settings.id, secrets_manager_instance_add_on_requested_at: nil)
        .update_all(secrets_manager_instance_add_on_requested_at: now, updated_at: now)

      # The raw write bypasses the loaded record; bring it back in step so
      # readers holding the same cached instance see the stamp immediately.
      current_settings.reset if current_settings.persisted?
      expire_settings

      updated == 1
    end

    # Gitlab::CurrentSettings is cached per Puma process for up to a minute,
    # and an update expires only the copy of the process that wrote it. The
    # enrollment gates pages and CI, so read the row itself, once per request,
    # or the other workers keep answering with the previous state. Only the
    # enrollment columns are loaded: the settings row is wide.
    def self.settings
      ::Gitlab::SafeRequestStore.fetch(SETTINGS_REQUEST_STORE_KEY) do
        ::ApplicationSetting.select(*SETTINGS_COLUMNS).last&.tap(&:readonly!) || fallback_settings
      end
    end

    # No row yet (a fresh install before its first settings write, or specs):
    # a read-only copy, so no caller can write through the shared
    # CurrentSettings record. A Gitlab::FakeApplicationSettings (rake with
    # pending migrations) is returned as is: it is not ActiveRecord and
    # cannot persist. The row query above still needs a database.
    def self.fallback_settings
      current = ::Gitlab::CurrentSettings.current_application_settings
      return current unless current.is_a?(::ApplicationSetting)

      current.dup.tap(&:readonly!)
    end
    private_class_method :fallback_settings

    # Writers call this so a later read in the same request sees the write.
    def self.expire_settings
      ::Gitlab::SafeRequestStore.delete(SETTINGS_REQUEST_STORE_KEY)
    end

    def self.enrollment_allowed?
      !::Gitlab.com? && # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- instance enrollment is self-managed only
        ::License.feature_available?(:native_secrets_management)
    end

    # Gates the instance trial and add-on mutations and the entitlement query.
    # Self-managed only: gitlab.com keys entitlement by top-level group, not by instance.
    def self.paid_experience_allowed?
      !::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        ::License.feature_available?(:native_secrets_management)
    end

    # Anything but an online cloud license (offline, legacy, or none) has no CDot
    # connectivity, so no trial can start; the entitlement state cannot tell this apart.
    # GitLab.com entitles per namespace, so it is never offline whatever its license shape.
    def self.offline_license?
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      !::License.current&.online_cloud_license?
    end
  end
end

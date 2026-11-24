# frozen_string_literal: true

module EE
  # PersonalAccessToken EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `PersonalAccessToken` model
  module PersonalAccessToken
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    prepended do
      include FromUnion

      has_one :workspace,
        class_name: 'RemoteDevelopment::Workspace',
        inverse_of: :personal_access_token,
        foreign_key: :personal_access_token_id

      scope :with_expires_at_after, ->(max_lifetime) { where(revoked: false).where('expires_at > ?', max_lifetime) }
      scope :expires_in, ->(within) { not_revoked.where('expires_at > CURRENT_DATE AND expires_at <= ?', within) }
      scope :created_on_or_after, ->(date) { active.where('created_at >= ?', date) }

      with_options if: :expiration_policy_enabled? do
        validate :expires_at_before_max_expiry_date
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      def pluck_names
        pluck(:name)
      end

      def with_invalid_expires_at(max_lifetime, limit = 1_000)
        from_union(
          [
            with_expires_at_after(max_lifetime).limit(limit)
          ]
        )
      end

      # Disable lookup by token (token auth) when PATs disabled (FIPS)
      override :find_by_token
      def find_by_token(token)
        return if ::Gitlab::CurrentSettings.personal_access_tokens_disabled?

        pat_token = super

        personal_access_tokens_disabled_by_enterprise_group = pat_token&.user&.enterprise_user? &&
          pat_token.user.enterprise_group.disable_personal_access_tokens?
        return if personal_access_tokens_disabled_by_enterprise_group

        pat_token
      end
    end

    private

    def expiration_policy_enabled?
      instance_level_expiration_policy_enabled?
    end

    def instance_level_expiration_policy_enabled?
      expiration_policy_licensed? &&
        expiry_date_calculator.instance_level_max_expiry_date
    end

    def max_expiry_date
      expiry_date_calculator.max_expiry_date
    end

    def allow_expires_at_to_be_empty?
      !EE::Gitlab::PersonalAccessTokens::ServiceAccountTokenValidator.new(user).expiry_enforced?
    end

    def expires_at_before_max_expiry_date
      return if expires_at.blank?
      return unless expires_at > max_expiry_date

      errors.add(
        :expires_at,
        format(_("must be before %{expiry_date}"), expiry_date: max_expiry_date)
      )
    end

    def expiration_policy_licensed?
      License.feature_available?(:personal_access_token_expiration_policy)
    end

    def expiry_date_calculator
      EE::Gitlab::PersonalAccessTokens::ExpiryDateCalculator.new(user)
    end
    strong_memoize_attr :expiry_date_calculator

    override :set_group_id
    def set_group_id
      self.group_id = user.enterprise_group_id if user.enterprise_user?
      self.group_id = user.provisioned_by_group.root_ancestor.id if user.service_account? && user.provisioned_by_group

      super
    end
  end
end

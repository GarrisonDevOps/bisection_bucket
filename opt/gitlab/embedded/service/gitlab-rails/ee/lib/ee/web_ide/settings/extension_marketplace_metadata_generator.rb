# frozen_string_literal: true

module EE
  module WebIde
    module Settings
      module ExtensionMarketplaceMetadataGenerator
        extend ActiveSupport::Concern

        # NOTE: Please see the note for DISABLED_REASONS in the relevant CE module
        EE_DISABLED_REASONS = %i[
          enterprise_group_disabled
        ].to_h { |reason| [reason, reason] }.freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :disabled_reasons
          def disabled_reasons
            super.merge(EE_DISABLED_REASONS).freeze
          end

          override :build_metadata_for_user
          def build_metadata_for_user(user:, marketplace_home_url:)
            return metadata_disabled(:enterprise_group_disabled) unless enabled_for_enterprise_group?(user)

            super
          end

          private

          def enabled_for_enterprise_group?(user)
            return true unless user.enterprise_user? && user.enterprise_group

            user.enterprise_group.enterprise_users_extensions_marketplace_enabled?
          end
        end
      end
    end
  end
end

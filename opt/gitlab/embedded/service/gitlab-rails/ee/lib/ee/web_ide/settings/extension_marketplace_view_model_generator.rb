# frozen_string_literal: true

module EE
  module WebIde
    module Settings
      module ExtensionMarketplaceViewModelGenerator
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          # @param [Symbol] disabled_reason The reason why the extension marketplace is disabled
          # @param [User] user
          # @return [Hash] Extra attributes to be added to the view model
          override :gallery_disabled_extra_attributes
          def gallery_disabled_extra_attributes(disabled_reason:, user:)
            return enterprise_group_disabled_attributes(user) if disabled_reason == :enterprise_group_disabled

            super
          end

          private

          # @param [User] user
          # @return [Hash] Extra attributes for when the user's enterprise group has disabled the extension marketplace
          def enterprise_group_disabled_attributes(user)
            group = user.enterprise_group

            {
              enterprise_group_name: group.full_name,
              enterprise_group_url: ::Gitlab::Routing.url_helpers.group_url(group)
            }
          end
        end
      end
    end
  end
end

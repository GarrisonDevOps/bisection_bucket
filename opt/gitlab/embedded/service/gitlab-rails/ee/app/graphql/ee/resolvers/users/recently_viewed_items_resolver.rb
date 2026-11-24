# frozen_string_literal: true

module EE
  module Resolvers
    module Users
      module RecentlyViewedItemsResolver
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :authorized_to_read_item?
        def authorized_to_read_item?(item)
          return Ability.allowed?(current_user, :read_epic, item) if item.is_a?(Epic)

          super
        end
      end
    end
  end
end

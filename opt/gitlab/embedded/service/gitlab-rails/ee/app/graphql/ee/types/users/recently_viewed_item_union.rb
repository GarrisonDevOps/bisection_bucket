# frozen_string_literal: true

module EE
  module Types
    module Users
      module RecentlyViewedItemUnion
        extend ActiveSupport::Concern

        prepended do
          possible_types ::Types::EpicType
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :resolve_type
          def resolve_type(object, _context)
            case object
            when Epic
              ::Types::EpicType
            else
              super
            end
          end
        end
      end
    end
  end
end

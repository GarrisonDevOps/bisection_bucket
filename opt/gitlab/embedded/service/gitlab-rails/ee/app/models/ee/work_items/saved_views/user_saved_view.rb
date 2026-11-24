# frozen_string_literal: true

module EE
  module WorkItems
    module SavedViews
      module UserSavedView
        extend ActiveSupport::Concern
        class_methods do
          extend ::Gitlab::Utils::Override

          override :user_saved_view_limit
          def user_saved_view_limit(namespace)
            namespace.licensed_feature_available?(:increased_saved_views_limit) ? 100 : super
          end
        end
      end
    end
  end
end

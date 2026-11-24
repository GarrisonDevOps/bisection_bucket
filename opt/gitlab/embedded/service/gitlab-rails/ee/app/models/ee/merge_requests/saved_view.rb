# frozen_string_literal: true

module EE
  module MergeRequests
    module SavedView
      extend ActiveSupport::Concern

      EE_MAX_VIEWS_PER_USER = 100

      class_methods do
        extend ::Gitlab::Utils::Override

        override :views_limit
        def views_limit
          return EE_MAX_VIEWS_PER_USER if ::License.feature_available?(:increased_saved_views_limit)

          super
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Gitlab
    module Tracking
      module Destinations
        module Snowplow
          extend ActiveSupport::Concern

          class_methods do
            extend ::Gitlab::Utils::Override

            override :dedicated?
            def dedicated?
              ::Gitlab::Dedicated.feature_available?(:snowplow_dedicated_app_id) || super
            end
          end
        end
      end
    end
  end
end

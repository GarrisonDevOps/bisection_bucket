# frozen_string_literal: true

module EE
  module Projects
    module Analytics
      module CycleAnalytics
        module ValueStreamsController
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          prepended do
            before_action :value_stream, only: %i[edit]
          end
        end
      end
    end
  end
end

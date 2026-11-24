# frozen_string_literal: true

module EE
  module Types
    module Analytics
      module CycleAnalytics
        module ValueStreams
          module StageMetricsType
            extend ActiveSupport::Concern

            prepended do
              field :series,
                description: 'Data series in the value stream stage.',
                resolver_method: :object,
                type: ::Types::Analytics::CycleAnalytics::ValueStreams::SeriesType,
                null: false,
                experiment: { milestone: '17.4' }
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Types
    module Analytics
      module CycleAnalytics
        module ValueStreams
          module StageType
            extend ActiveSupport::Concern

            prepended do
              field :start_event_label,
                ::Types::LabelType,
                null: true,
                description: 'Label associated with start event.'

              field :end_event_label,
                ::Types::LabelType,
                null: true,
                description: 'Label associated with end event.'
            end
          end
        end
      end
    end
  end
end

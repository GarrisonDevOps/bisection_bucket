# frozen_string_literal: true

module EE
  module Types
    module Analytics
      module CycleAnalytics
        module ValueStreams
          module StageItemsType
            extend ActiveSupport::Concern
            extend ::Gitlab::Utils::Override

            prepended do
              field :duration_in_milliseconds,
                ::GraphQL::Types::BigInt,
                null: true,
                description: 'Duration of item on stage in milliseconds.'
            end

            override :record
            def record
              return super if object.is_a?(Issuable)

              object.issuable
            end
          end
        end
      end
    end
  end
end

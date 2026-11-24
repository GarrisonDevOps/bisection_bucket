# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class EventLocationType < BaseUnion
        graphql_name 'GitlabSubscriptionUsageEventLocation'
        description 'Describes the location of a subscription usage event.'

        possible_types ::Types::ProjectType, ::Types::GroupType

        def self.resolve_type(object, _context)
          case object
          when Project
            ::Types::ProjectType
          when Group
            ::Types::GroupType
          else
            raise 'Unsupported subscription usage event location type'
          end
        end
      end
    end
  end
end

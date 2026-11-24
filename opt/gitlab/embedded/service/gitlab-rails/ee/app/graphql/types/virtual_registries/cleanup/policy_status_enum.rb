# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Cleanup
      class PolicyStatusEnum < BaseEnum
        graphql_name 'PolicyStatus'

        description 'Lists the status of a virtual registry cleanup policy'

        ::VirtualRegistries::Cleanup::Policy.statuses.each_key do |status|
          value status.upcase, description: "Cleanup policy status #{status}.", value: status
        end
      end
    end
  end
end

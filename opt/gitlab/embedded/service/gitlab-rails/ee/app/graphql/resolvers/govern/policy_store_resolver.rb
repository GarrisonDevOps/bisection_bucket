# frozen_string_literal: true

module Resolvers
  module Govern
    class PolicyStoreResolver < BaseResolver
      type ::Types::Govern::PolicyStoreType, null: true

      def resolve
        object.policy_store_experiment_active? ? object : nil
      end
    end
  end
end

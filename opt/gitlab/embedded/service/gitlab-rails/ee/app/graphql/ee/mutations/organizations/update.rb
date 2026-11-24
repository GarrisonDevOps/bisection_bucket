# frozen_string_literal: true

module EE
  module Mutations
    module Organizations
      module Update
        extend ActiveSupport::Concern

        prepended do
          argument :policy_store_experiment_enabled, GraphQL::Types::Boolean,
            required: false,
            experiment: { milestone: '19.4' },
            description: 'Opt the organization in to or out of the Policy Store experiment. ' \
              'Opting in returns an error when the experiment is not available to the ' \
              'organization; opting out is always accepted.'
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Types
    module Ci
      module CiCdSettingType
        extend ActiveSupport::Concern

        prepended do
          field :merge_trains_skip_train_allowed,
            GraphQL::Types::Boolean,
            null: false,
            description: 'Whether merge immediately is allowed for merge trains.',
            method: :merge_trains_skip_train_allowed?,
            authorize: :admin_project
          field :merge_train_enforcement,
            ::Types::Ci::MergeTrainEnforcementEnum,
            null: false,
            description: 'Merge train enforcement level for the project.',
            authorize: :admin_project
          field :merge_trains_enabled,
            GraphQL::Types::Boolean,
            null: true,
            description: 'Whether merge trains are enabled.',
            method: :merge_trains_enabled?
          field :max_pipelines_per_merge_train,
            GraphQL::Types::Int,
            null: true,
            description: 'Maximum number of parallel pipelines per merge train. When null, the plan limit applies.'
        end
      end
    end
  end
end

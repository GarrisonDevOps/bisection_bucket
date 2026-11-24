# frozen_string_literal: true

module EE
  module Types
    module Ci
      module PipelineInterface
        extend ActiveSupport::Concern

        prepended do
          orphan_types ::Types::Ci::PipelineMinimalAccessType
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :resolve_type
          def resolve_type(object, context)
            user = context[:current_user]

            return ::Types::Ci::PipelineType if Ability.allowed?(user, :read_pipeline, object)
            return ::Types::Ci::PipelineMinimalAccessType if Ability.allowed?(user, :read_pipeline_metadata, object)

            ::Types::Ci::PipelineType
          end
        end
      end
    end
  end
end

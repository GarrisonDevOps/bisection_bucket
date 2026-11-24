# frozen_string_literal: true

module Gitlab
  module Graphql
    module Limit
      class MlCandidateFieldCallCount < FieldCallCount
        def resolve(object:, arguments:, context:)
          project = ::Project.actor_from_id(object.object.project_id)
          return yield(object, arguments) if Feature.disabled?(:limit_ml_candidate_graphql_fields, project)

          super
        end
      end
    end
  end
end

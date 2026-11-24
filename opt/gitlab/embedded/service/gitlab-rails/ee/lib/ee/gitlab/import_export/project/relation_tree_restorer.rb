# frozen_string_literal: true

module EE
  module Gitlab
    module ImportExport
      module Project
        module RelationTreeRestorer
          extend ::Gitlab::Utils::Override

          EE_GROUP_MODELS = [Iteration].freeze

          private

          override :relations
          def relations
            relations = super
            relations.delete('ci_pipelines') if importable.gitlab_custom_project_template_import?
            relations
          end

          override :group_models
          def group_models
            super + EE_GROUP_MODELS
          end

          # Iteration cadences are existing records that are only referenced by iterations, never built or changed
          # on import. Validating them would run extra queries for every occurrence and warn about cadences that
          # were already invalid in the destination group.
          override :validate_built_relation?
          def validate_built_relation?(relation)
            super && !relation.is_a?(::Iterations::Cadence)
          end
        end
      end
    end
  end
end

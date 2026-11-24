# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module ProjectConfig
        module Compliance
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          EXCLUDED_SOURCES = [
            :security_orchestration_policy,
            :ondemand_dast_scan,
            :duo_workflow
          ].freeze

          override :content
          def content
            return unless available?
            return unless pipeline_configuration_full_path.present?
            return if pipeline_source_bridge && pipeline_source == :parent_pipeline

            return if EXCLUDED_SOURCES.include?(pipeline_source)

            path_file, path_project = pipeline_configuration_full_path.split('@', 2)
            ci_yaml_include({ 'project' => path_project, 'file' => path_file })
          end
          strong_memoize_attr :content

          private

          def pipeline_configuration_full_path
            return unless project

            project.compliance_pipeline_configuration_full_path
          end
          strong_memoize_attr :pipeline_configuration_full_path

          def available?
            project.licensed_feature_available?(:evaluate_group_level_compliance_pipeline)
          end
        end
      end
    end
  end
end

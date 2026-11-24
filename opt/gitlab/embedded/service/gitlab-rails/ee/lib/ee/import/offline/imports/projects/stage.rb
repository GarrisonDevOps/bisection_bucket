# frozen_string_literal: true

module EE
  module Import
    module Offline
      module Imports
        module Projects
          module Stage
            extend ::Gitlab::Utils::Override

            private

            def ee_config
              {
                push_rule: {
                  pipeline: ::BulkImports::Projects::Pipelines::PushRulePipeline,
                  stage: 4
                },
                vulnerabilities: {
                  pipeline: ::BulkImports::Projects::Pipelines::VulnerabilitiesPipeline,
                  stage: 6
                },
                user_contributions: {
                  stage: 7 # :pipeline not specified to move CE pipeline to a different stage
                },
                finisher: {
                  stage: 8 # :pipeline not specified to move CE pipeline to a different stage
                }
              }
            end

            override :config
            def config
              bulk_import.source_enterprise ? super.deep_merge(ee_config) : super
            end
          end
        end
      end
    end
  end
end

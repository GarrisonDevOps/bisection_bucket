# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Projects
        module SaveProjectService
          extend ::Gitlab::Utils::Override

          override :input_schema
          def input_schema
            super.deep_merge(
              properties: {
                use_custom_template: {
                  type: 'boolean',
                  description: 'Use a custom project template. Requires template_name or template_project_id. ' \
                    'Requires GitLab Premium or Ultimate.'
                },
                group_with_project_templates_id: {
                  type: 'integer',
                  description: 'Group ID that serves as the template source for group-level templates. ' \
                    'Optional for instance-level templates. Requires GitLab Premium or Ultimate.'
                },
                template_project_id: {
                  type: 'integer',
                  description: 'Project ID of a custom project template. Alternative to template_name. ' \
                    'Use with use_custom_template.'
                }
              }
            )
          end
        end
      end
    end
  end
end

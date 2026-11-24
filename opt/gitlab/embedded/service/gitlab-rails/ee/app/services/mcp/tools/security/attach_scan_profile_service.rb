# frozen_string_literal: true

module Mcp
  module Tools
    module Security
      class AttachScanProfileService < Base::GraphqlService
        include Availability

        MAX_IDS = ::Mutations::Security::ScanProfiles::SharedScopeResolution::MAX_IDS

        container_arguments project: :project_ids,
          group: :group_ids,
          record: { security_scan_profile_id: ->(id) { container_from_scan_profile(id) } }

        register_version '0.1.0', {
          toolset: :code_security,
          description: 'Attach a given security scan profile to the given groups and projects. ' \
            "project_ids and group_ids together can name at most #{MAX_IDS} ids.",
          input_schema: {
            type: 'object',
            properties: {
              security_scan_profile_id: {
                type: 'string',
                description: 'Global ID of the security scan profile to attach.'
              },
              project_ids: {
                type: 'array',
                description: 'Array of Global IDs of the projects. Required if `group_ids` not provided. ' \
                  "Together with group_ids, at most #{MAX_IDS} ids.",
                items: {
                  type: 'string'
                },
                minItems: 1,
                maxItems: MAX_IDS
              },
              group_ids: {
                type: 'array',
                description: 'Array of Global IDs of the groups. Required if `project_ids` not provided. ' \
                  "Together with project_ids, at most #{MAX_IDS} ids.",
                items: {
                  type: 'string'
                },
                minItems: 1,
                maxItems: MAX_IDS
              }
            },
            required: ['security_scan_profile_id'],
            additionalProperties: false
          },
          annotations: {
            title: 'Attach security scan profile',
            readOnlyHint: false,
            destructiveHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        override :governed_containers
        def governed_containers(arguments)
          total = Array(arguments[:project_ids]).size + Array(arguments[:group_ids]).size

          if total > MAX_IDS
            raise TooManyContainersError, "project_ids and group_ids together cannot name more than #{MAX_IDS} ids"
          end

          super
        end

        private

        def licensed_feature
          :security_scan_profiles
        end

        def container_from_scan_profile(id)
          profile = ::Security::ScanProfile.find_by_id(record_id_from(id, [::Security::ScanProfile]))

          container_from_namespace(profile&.namespace)
        end

        def graphql_tool_class
          Mcp::Tools::Security::AttachScanProfileTool
        end

        def perform_v0_1_0(arguments)
          execute_graphql_tool(arguments)
        end

        override :perform_default
        def perform_default(arguments = {})
          perform_v0_1_0(arguments)
        end
      end
    end
  end
end

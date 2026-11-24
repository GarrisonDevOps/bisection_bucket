# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class SeedFoundationalFlowsService
        # Foundational flows live in the default organization, whichever organization triggers seeding:
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/637664
        def initialize
          @errors = []
          @default_organization = ::Organizations::Organization.default_organization # rubocop:disable Gitlab/AvoidDefaultOrganization -- foundational flows are shared, see comment above

          raise StandardError, 'Default organization not found' unless @default_organization
        end

        def execute
          ::Ai::Catalog::FoundationalFlow.find_each do |workflow_def|
            seed_workflow_definition(workflow_def)
          end

          if @errors.empty?
            ServiceResponse.success(message: 'Foundational flows seeded successfully')
          else
            ServiceResponse.error(message: 'Failed to seed some foundational flows', payload: @errors)
          end
        end

        private

        attr_reader :errors, :default_organization

        def seed_workflow_definition(workflow_def)
          workflow_name = workflow_def.display_name
          foundational_reference = workflow_def.foundational_flow_reference

          item = ::Ai::Catalog::Item
                   .in_organization(default_organization)
                   .with_foundational_flow_reference(foundational_reference)
                   .first_or_initialize

          is_new_record = item.new_record?

          item.assign_attributes(
            name: workflow_name,
            description: workflow_def.description,
            item_type: ::Ai::Catalog::Item::FLOW_TYPE,
            verification_level: :gitlab_maintained,
            visibility: :public,
            project_id: nil,
            foundational_flow_reference: foundational_reference
          )

          build_initial_version(item) if is_new_record

          @errors << { name: workflow_name, errors: item.errors.full_messages } unless save_item(item)
        end

        def build_initial_version(item)
          yaml_definition = minimal_flow_yaml(item)

          item.build_new_version(
            schema_version: ::Ai::Catalog::ItemVersion::FLOW_SCHEMA_VERSION,
            version: '1.0.0',
            definition: YAML.safe_load(
              yaml_definition, permitted_classes: [], aliases: false).merge('yaml_definition' => yaml_definition),
            release_date: Time.zone.now
          )
        end

        def minimal_flow_yaml(_item)
          <<~YAML
          version: v1
          environment: ambient
          components:
            - name: foundationalFlow
              type: AgentComponent
              prompt_id: foundationalFlow
              prompt_version: "0.0.0"
          routers: []
          flow:
            entry_point: foundationalFlow
            inputs: []
          YAML
        end

        def save_item(item)
          ApplicationRecord.transaction do
            item.save!

            item.update!(latest_released_version: item.latest_version) if item.latest_version&.released?
          end

          true
        rescue ActiveRecord::RecordInvalid
          false
        end
      end
    end
  end
end

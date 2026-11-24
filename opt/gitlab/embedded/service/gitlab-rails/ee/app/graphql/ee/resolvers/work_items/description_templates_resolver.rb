# frozen_string_literal: true

module EE
  module Resolvers
    module WorkItems
      module DescriptionTemplatesResolver
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::WorkItems::DescriptionTemplateDefaults

        override :resolve
        def resolve(**args)
          templates = super

          add_settings_default_template(templates)
        end

        private

        override :fetch_root_templates_project
        def fetch_root_templates_project(namespace)
          unless namespace.is_a?(::Group) && !namespace.namespace_template_setting&.file_template_project_id
            return super
          end

          namespace.ancestors(hierarchy_order: :asc).with_custom_file_templates.first&.checked_file_template_project
        end

        def add_settings_default_template(templates)
          project = fetch_root_templates_project(namespace)
          return templates unless project&.issues_template.present?

          settings_template = SettingsDefaultTemplate.new(
            project_id: project.id,
            content: project.issues_template
          )

          result = [settings_template] + Array.wrap(templates)
          result.presence
        end
      end
    end
  end
end

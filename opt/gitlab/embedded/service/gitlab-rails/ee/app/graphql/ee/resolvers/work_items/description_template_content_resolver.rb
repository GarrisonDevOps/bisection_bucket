# frozen_string_literal: true

module EE
  module Resolvers
    module WorkItems
      module DescriptionTemplateContentResolver
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override
        include ::WorkItems::DescriptionTemplateDefaults

        override :resolve
        def resolve(template_content_input:)
          if template_content_input[:name] == DEFAULT_SETTINGS_TEMPLATE_NAME
            return resolve_settings_default_template(template_content_input)
          end

          super
        end

        private

        def resolve_settings_default_template(template_content_input)
          project = ::Project.find_by_id(template_content_input[:project_id])
          return unless project

          authorize!(project.project_namespace)

          return unless project.issues_template.present?

          SettingsDefaultTemplate.new(
            content: project.issues_template,
            project_id: project.id
          )
        end

        override :authorize_template!
        def authorize_template!(template_project, from_namespace)
          # If the instance wide default template repository is this one, we don't need to authorize. Assume that all
          # users in the instance can read the template
          if ::License.feature_available?(:custom_file_templates) &&
              ::Gitlab::CurrentSettings.file_template_project == template_project
            return
          end

          # If a target namespace is provided, we'll check if:
          # * The current user can read this namespace
          # * The checked_file_template_project of any ancestor of this namespace is the template's project
          if from_namespace
            target_namespace = Routable.find_by_full_path(from_namespace)
            target_namespace = target_namespace.project_namespace if target_namespace.is_a?(Project)

            authorize!(target_namespace)

            return if target_namespace.self_and_ancestors(skope: ::Namespace).any? do |n|
              n.checked_file_template_project&.id == template_project.id
            end
          end

          # If we didn't return from the above 2 checks, check if we can at least read the namespace of the project
          # related to the template
          super
        end
      end
    end
  end
end

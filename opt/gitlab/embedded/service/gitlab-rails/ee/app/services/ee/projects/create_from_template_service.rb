# frozen_string_literal: true

module EE
  module Projects
    module CreateFromTemplateService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :template_project_id, :subgroup_id

      override :initialize
      def initialize(user, params)
        super

        @template_project_id = @params.delete(:template_project_id).to_i if @params[:template_project_id].present?
        @subgroup_id = @params.delete(:group_with_project_templates_id).presence
      end

      override :execute
      def execute
        return super unless use_custom_template?

        return project unless validate_template_request! && validate_group_template!

        override_params = params.dup
        params[:custom_template] = template_project if template_project

        ::Projects::GitlabProjectsImportService.new(current_user, params, override_params, import_type: 'gitlab_custom_project_template').execute
      end

      private

      def validate_template_request!
        return true if template_requested?

        project.errors.add(:use_custom_template, 'must be used with template_name or template_project_id')
        false
      end

      def validate_group_template!
        if subgroup_id && !valid_project_namespace?
          project.errors.add(:namespace, _("is not a descendant of the Group owning the template"))
          return false
        end

        return true if template_project.present?

        if template_project_id.present?
          project.errors.add(
            :template_project_id,
            _("%{template_project_id} is unknown or invalid") % { template_project_id: template_project_id }
          )
        else
          project.errors.add(:template_name, _("'%{template_name}' is unknown or invalid") % { template_name: template_name })
        end

        false
      end

      def use_custom_template?
        strong_memoize(:use_custom_template) do
          ::Gitlab::Utils.to_boolean(params.delete(:use_custom_template)) && ::Gitlab::CurrentSettings.custom_project_templates_enabled?
        end
      end

      override :built_in_template_allowed?
      def built_in_template_allowed?
        case target_namespace
        when ::Group
          return true if target_namespace.allow_built_in_project_templates?

          project.errors.add(:group, _("has disabled the use of built-in project templates"))
          false
        when ::Namespaces::UserNamespace
          if ::Gitlab::CurrentSettings.current_application_settings.allow_instance_built_in_project_templates?
            return true
          end

          project.errors.add(:instance, _("has disabled the use of built-in project templates"))
          false
        else
          true
        end
      end

      def target_namespace
        strong_memoize(:target_namespace) do
          ::Namespace.find_by_id(params[:namespace_id])
        end
      end

      # rubocop: disable CodeReuse/ActiveRecord -- find_by needed for exact template name match
      def template_project
        strong_memoize(:template_project) do
          template =
            if template_project_id.present?
              current_user.available_custom_project_templates(project_id: template_project_id, subgroup_id: subgroup_id).first
            else
              templates = current_user.available_custom_project_templates(search: template_name, subgroup_id: subgroup_id)
              templates.find_by(name: template_name) || templates.first
            end

          can?(current_user, :read_code, template) ? template : nil
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def template_requested?
        template_name.present? || template_project_id.is_a?(Integer)
      end

      # rubocop: disable CodeReuse/ActiveRecord
      def valid_project_namespace?
        templates_owner = ::Group.find(subgroup_id).parent

        return false unless templates_owner

        templates_owner.self_and_descendants.exists?(id: project.namespace_id)
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end

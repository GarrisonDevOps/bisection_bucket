# frozen_string_literal: true

module Mutations
  module Projects
    class ProjectSettingsUpdate < BaseMutation
      graphql_name 'ProjectSettingsUpdate'

      include FindsProject
      include Gitlab::Utils::StrongMemoize

      authorize :admin_project
      authorize_granular_token permissions: :update_project, boundary_argument: :full_path, boundary_type: :project

      argument :full_path,
        GraphQL::Types::ID,
        required: true,
        description: 'Full Path of the project the settings belong to.'

      argument :duo_features_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether GitLab Duo features are enabled for the project.'

      argument :tool_approval_for_session_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether tool approval for Duo Workflow sessions is enabled for the project.'

      argument :duo_auto_mode_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether Duo Agent Platform auto mode is enabled for the project.'

      argument :duo_context_exclusion_settings,
        Types::Projects::Input::DuoContextExclusionSettingsInputType,
        required: false,
        description: 'Settings for excluding files from Duo context.'

      argument :web_based_commit_signing_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether web-based commit signing is enabled for the project.',
        experiment: { milestone: '18.2' }

      argument :ai_audit_events_storage_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether AI audit events are stored for the project.',
        experiment: { milestone: '19.2' }

      field :project_settings,
        Types::Projects::SettingType,
        null: false,
        description: 'Project settings after mutation.'

      argument :duo_sast_vr_workflow_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether SAST Vulnerability Resolution workflow is enabled for the project.'

      argument :duo_sast_fp_detection_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether SAST False Positive Detection is enabled for the project.'

      argument :duo_secret_detection_fp_enabled,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Indicates whether Secret Detection False Positive Detection is enabled for the project.'

      def resolve(full_path:, **args)
        raise raise_resource_not_available_error! unless allowed?

        project = find_object(full_path)
        raise_resource_not_available_error! unless can_access?(project, args)

        if args.key?(:ai_audit_events_storage_enabled) &&
            !Ability.allowed?(current_user, :update_storage_ai_audit_events, project)
          raise_resource_not_available_error!
        end

        # Process duo_context_exclusion_settings to convert it to a hash if present
        if args[:duo_context_exclusion_settings].present?
          args[:duo_context_exclusion_settings] = args[:duo_context_exclusion_settings].to_h
        end

        args.compact!

        raise Gitlab::Graphql::Errors::ArgumentError, 'Must provide at least one argument' if args.empty?

        ::Projects::UpdateService.new(project, current_user, { project_setting_attributes: args }).execute

        {
          project_settings: project.project_setting,
          errors: errors_on_object(project.project_setting)
        }
      end

      private

      def allowed?
        return true if ::Gitlab::Saas.feature_available?(:duo_chat_on_saas)
        return true if ::Gitlab::Saas.feature_available?(:repositories_web_based_commit_signing)
        return false unless ::License.feature_available?(:code_suggestions)

        ::GitlabSubscriptions::AddOnPurchase.active_duo_add_ons_exist?(:instance)
      end

      def can_access?(project, args)
        return false unless project

        return true if Ability.allowed?(current_user, :admin_project, project)

        return true if args.keys == [:ai_audit_events_storage_enabled] &&
          Ability.allowed?(current_user, :update_storage_ai_audit_events, project)

        only_sec_ai_settings?(args, project) &&
          Ability.allowed?(current_user, :update_sec_ai_workflow_settings, project)
      end

      def only_sec_ai_settings?(args, project)
        setting_flags = ::EE::Projects::UpdateService::AI_WORKFLOW_SETTING_FEATURE_FLAGS
        setting_keys = args.keys & setting_flags.keys

        # Ensure the request contains only recognised AI workflow settings (no other arguments)
        # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- iterating over a fixed constant of setting-to-flag mappings
        setting_keys.any? &&
          setting_keys.size == args.keys.size &&
          setting_keys.all? { |key| Feature.enabled?(setting_flags[key], project) }
        # rubocop:enable Gitlab/FeatureFlagKeyDynamic
      end
    end
  end
end

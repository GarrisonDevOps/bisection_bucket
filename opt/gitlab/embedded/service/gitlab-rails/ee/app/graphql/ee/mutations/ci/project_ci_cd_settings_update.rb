# frozen_string_literal: true

module EE
  module Mutations
    module Ci
      module ProjectCiCdSettingsUpdate
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          argument :merge_pipelines_enabled, GraphQL::Types::Boolean,
            required: false,
            description: 'Indicates if merged results pipelines are enabled for the project.'

          argument :merge_trains_enabled, GraphQL::Types::Boolean,
            required: false,
            description: 'Indicates if merge trains are enabled for the project.'

          argument :merge_trains_skip_train_allowed, GraphQL::Types::Boolean,
            required: false,
            description: 'Indicates whether an option is allowed to merge without refreshing the merge train. ' \
              'Ignored unless the `merge_trains_skip_train` feature flag is also enabled.'

          argument :merge_train_enforcement, ::Types::Ci::MergeTrainEnforcementEnum,
            required: false,
            description: 'Merge train enforcement level for the project.'

          argument :max_pipelines_per_merge_train, GraphQL::Types::Int,
            required: false,
            description: 'Maximum number of parallel pipelines per merge train.'
        end

        override :resolve
        def resolve(**args)
          super.tap do |result|
            ci_cd_settings = result[:ci_cd_settings]
            audit_project = ci_cd_settings.project

            if ci_cd_settings.inbound_job_token_scope_enabled_previously_changed?
              audit_inbound_job_token_enabled_changed(
                audit_project,
                ci_cd_settings,
                current_user,
                ci_cd_settings.inbound_job_token_scope_enabled
              )
            end
          end
        end

        private

        override :project_update_params
        def project_update_params(project, **args)
          result = super
          result.merge!(
            args.slice(
              :merge_pipelines_enabled,
              :merge_trains_enabled,
              :max_pipelines_per_merge_train,
              :merge_train_enforcement
            )
          )

          if ::Feature.enabled?(:merge_trains_skip_train, project)
            result.merge!(args.slice(:merge_trains_skip_train_allowed))
          end

          result.compact
        end

        def audit_inbound_job_token_enabled_changed(scope, target, author, inbound_job_token_scope_enabled)
          audit_action = inbound_job_token_scope_enabled ? 'enabled' : 'disabled'
          audit_message = "Secure ci_job_token was #{audit_action} for inbound"
          event_name = "secure_ci_job_token_inbound_#{audit_action}"

          audit_context = {
            name: event_name,
            author: author,
            scope: scope,
            target: target,
            message: audit_message
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end

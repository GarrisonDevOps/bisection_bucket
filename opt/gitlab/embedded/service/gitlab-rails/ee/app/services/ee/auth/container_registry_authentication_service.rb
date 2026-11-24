# frozen_string_literal: true

module EE
  module Auth
    module ContainerRegistryAuthenticationService
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      StorageError = Class.new(StandardError)

      override :execute
      def execute(authentication_abilities:, personal_access_token: nil)
        super
      rescue StorageError
        error(
          'DENIED',
          status: 403,
          message: format(
            _("Your action has been rejected because the namespace storage limit has been reached. " \
            "For more information, " \
            "visit %{doc_url}."),
            doc_url: Rails.application.routes.url_helpers.help_page_url('user/storage_usage_quotas.md')
          )
        )
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        private

        override :patterns_metadata
        def patterns_metadata(project, _user, actions)
          super.merge(tag_immutable_patterns: tag_immutable_patterns(project, actions))
        end

        def tag_immutable_patterns(project, actions)
          return unless project
          return unless project.licensed_feature_available?(:container_registry_immutable_tag_rules)
          return unless (actions & %w[push delete *]).any?

          project.container_registry_protection_tag_rules.immutable.pluck_tag_name_patterns.presence
        end
      end

      private

      override :can_access?
      def can_access?(requested_project, requested_action)
        if ::Gitlab.maintenance_mode? && requested_action != 'pull'
          @access_denied_in_maintenance_mode = true # rubocop:disable Gitlab/ModuleWithInstanceVariables
          return false
        end

        raise StorageError if storage_error?(requested_project, requested_action)

        super
      end

      override :extra_info
      def extra_info
        return super unless access_denied_in_maintenance_mode?

        super.merge!({
          message: 'Write access denied in maintenance mode',
          write_access_denied_in_maintenance_mode: true
        })
      end

      override :find_or_create_repository_from_path
      def find_or_create_repository_from_path(path)
        new_record = !::ContainerRepository.find_by_path(path)

        repository = super(path)
        audit_repository_created(repository) if new_record

        repository
      end

      def audit_repository_created(repository)
        audit_context = {
          name: "container_repository_created",
          author: current_user || deploy_token&.user || ::Gitlab::Audit::DeployTokenAuthor.new,
          scope: repository.project,
          target: repository,
          target_details: repository.path,
          message: "Container repository #{repository.path} created"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def access_denied_in_maintenance_mode?
        @access_denied_in_maintenance_mode
      end

      def storage_error?(project, action)
        return false unless project
        return false unless action == 'push'

        project.root_ancestor.over_storage_limit?
      end
    end
  end
end

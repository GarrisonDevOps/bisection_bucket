# frozen_string_literal: true

module EE
  module Import
    module GithubService
      include ::Gitlab::Utils::StrongMemoize
      include ::Gitlab::InternalEventsTracking
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(access_params, provider)
        # Callers strip this for PAT, API, and Gitea imports; repeating it here keeps the service self-sufficient.
        params[:optional_stages]&.delete(:continuous_sync) unless continuous_sync_available?(provider)

        super.tap { |result| track_continuous_sync_enabled(result[:project]) }
      end

      override :extra_project_attrs
      def extra_project_attrs
        attrs = super.merge(ci_cd_only: params[:ci_cd_only])
        return attrs unless continuous_sync_requested?

        # Everything GitHub-related is resolved here; the block only builds the row, which is then
        # saved in the project's transaction so it lands with the project or not at all.
        row_attrs = sync_repository_attrs(github_account)

        attrs.merge(
          import_data: { data: { user_credential_id: user_credential.id } },
          relations_block: ->(project) { project.build_import_sync_repository(row_attrs) }
        )
      end

      override :validate_context
      def validate_context
        super || validate_continuous_sync_license || validate_user_credential || validate_over_repository_size_limit
      end

      def validate_continuous_sync_license
        return unless continuous_sync_requested?
        return if target_namespace.licensed_feature_available?(:github_continuous_sync)

        error(
          s_("GithubImport|Not available with updates on. Choose a Premium or Ultimate group."), :unprocessable_entity
        )
      end

      def validate_user_credential
        return unless continuous_sync_requested?
        return if user_credential

        error(s_("GithubImport|To import with updates on, authorize GitHub again."), :unprocessable_entity)
      end

      def validate_over_repository_size_limit
        return unless over_repository_size_limit?

        error(oversize_error_message, :unprocessable_entity)
      end

      def repository_size_limit
        target_namespace.actual_repository_size_limit
      end
      strong_memoize_attr :repository_size_limit

      def over_repository_size_limit?
        repository_size_limit > 0 && repo[:size] > repository_size_limit
      end

      def oversize_error_message
        format(
          s_('GithubImport|"%{repository_name}" size (%{repository_size}) is larger than the limit of %{limit}.'),
          {
            repository_name: repo[:name],
            repository_size: number_to_human_size(repo[:size]),
            limit: number_to_human_size(repository_size_limit)
          }
        )
      end

      private

      def continuous_sync_available?(provider)
        provider == :github && ::Feature.enabled?(:github_continuous_import, current_user)
      end

      def continuous_sync_requested?
        ::Gitlab::Utils.to_boolean(params.dig(:optional_stages, :continuous_sync), default: false)
      end

      def track_continuous_sync_enabled(project)
        return unless continuous_sync_requested? && project&.persisted?

        track_internal_event(
          'enable_import_continuous_sync',
          user: current_user,
          project: project,
          namespace: project.namespace,
          additional_properties: { label: project.import_type }
        )
      end

      def github_account
        client.octokit.user.to_h
      end
      strong_memoize_attr :github_account

      def user_credential
        ::Import::UserCredential.for_account(
          user: current_user,
          provider: :github,
          provider_host: URI.parse(repo[:clone_url]).host,
          provider_account_xid: github_account[:id]
        ).first
      end
      strong_memoize_attr :user_credential

      def sync_repository_attrs(account)
        repository = repo.to_h

        {
          connected_by_user: current_user,
          provider: :github,
          provider_account_xid: account[:id],
          provider_account_login: account[:login],
          provider_repository_xid: repository[:id],
          provider_repository_node_id: repository[:node_id],
          provider_full_name: repository[:full_name],
          provider_default_branch: repository[:default_branch],
          authority_state: :provisioning
        }
      end
    end
  end
end

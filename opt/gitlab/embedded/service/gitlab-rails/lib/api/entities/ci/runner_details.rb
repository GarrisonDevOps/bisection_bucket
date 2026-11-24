# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerDetails < RunnerWithUuid
        include Gitlab::Utils::StrongMemoize
        include Gitlab::Allowable

        # NOTE: instance runners are exposed by default to any authenticated user,
        # remember to protect any sensitive fields
        expose :tag_list
        expose :run_untagged
        expose :locked
        expose :maximum_timeout
        expose :access_level
        expose :token_expires_at,
          documentation: {
            type: 'DateTime', example: '2025-01-01T00:00:00.000Z',
            desc: 'Expiry time of the runner authentication token. `null` if the token does not expire. ' \
              'Returned only to users who can view sensitive runner data. For instance runners, only administrators.'
          },
          if: ->(runner, options) { can?(options[:current_user], :read_runner_sensitive_data, runner) }
        # TODO: remove in v5 https://gitlab.com/gitlab-org/gitlab/-/issues/457128
        expose(:version, documentation: {
          type: 'String',
          desc: 'Version of the runner, from its most recently contacted runner manager. ' \
            'Deprecated. Use the runner manager fields in the GraphQL API instead.'
        }) { |runner, _options| latest_runner_manager(runner)&.version }
        expose(:revision, documentation: {
          type: 'String',
          desc: 'Revision of the runner, from its most recently contacted runner manager. ' \
            'Deprecated. Use the runner manager fields in the GraphQL API instead.'
        }) { |runner, _options| latest_runner_manager(runner)&.revision }
        expose(:platform, documentation: {
          type: 'String',
          desc: 'Platform of the runner, from its most recently contacted runner manager. ' \
            'Deprecated. Use the runner manager fields in the GraphQL API instead.'
        }) { |runner, _options| latest_runner_manager(runner)&.platform }
        expose(:architecture, documentation: {
          type: 'String',
          desc: 'Architecture of the runner, from its most recently contacted runner manager. ' \
            'Deprecated. Use the runner manager fields in the GraphQL API instead.'
        }) { |runner, _options| latest_runner_manager(runner)&.architecture }
        expose :contacted_at
        expose :maintenance_note do |runner, options|
          runner.maintenance_note if Ability.allowed?(options[:current_user], :update_runner, runner)
        end

        expose :projects, with: Entities::BasicProjectDetails, if: ->(_, options) {
          options[:include_projects]
        }, documentation: { is_array: true } do |runner, options|
          next runner.projects if options[:current_user].can_read_all_resources?

          options[:current_user].authorized_projects.id_in(runner.project_ids)
        end
        expose :groups, with: Entities::BasicGroupDetails, documentation: { is_array: true } do |runner, options|
          next runner.groups if options[:current_user].can_read_all_resources?

          options[:current_user].authorized_groups.id_in(runner.namespace_ids)
        end

        def latest_runner_manager(runner)
          strong_memoize_with(:latest_runner_manager, runner) do
            runner.runner_managers.order_contacted_at_desc.first
          end
        end
      end
    end
  end
end

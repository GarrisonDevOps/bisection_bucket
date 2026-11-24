# frozen_string_literal: true

module EE
  module Ci
    module Runners
      # Unregisters CI Runners in bulk and logs an audit event
      #
      module BulkDeleteRunnersService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super.tap do |result|
            next unless runners && result.success?

            audit_event(result.payload[:deleted_models])
          end
        end

        private

        def audit_event(runners)
          runners = runners.to_a
          runner_short_shas = runners.map(&:short_sha)

          ::Gitlab::Audit::Auditor.audit(
            name: 'ci_runners_bulk_deleted',
            author: current_user,
            scope: current_user,
            target: ::Gitlab::Audit::NullTarget.new,
            message: "Deleted CI runners in bulk. Runner tokens: [#{runner_short_shas.join(', ')}]",
            details: {
              errors: runners.filter_map { |runner| runner.errors.full_messages.presence }.join(', ').presence,
              runner_ids: runners.map(&:id),
              runner_short_shas: runner_short_shas
            })
        end
      end
    end
  end
end

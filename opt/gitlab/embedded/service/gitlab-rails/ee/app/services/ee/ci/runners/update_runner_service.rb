# frozen_string_literal: true

module EE
  module Ci
    module Runners
      module UpdateRunnerService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute(params)
          return super unless params.include?(:tag_list)

          previous_tag_list = runner.tag_list.sort

          super.tap do |result|
            audit_tag_list_change(previous_tag_list) if result.success?
          end
        end

        private

        def audit_tag_list_change(previous_tag_list)
          current_tag_list = runner.tag_list.sort
          return if current_tag_list == previous_tag_list

          ::AuditEvents::RunnerAuditEventService.new(
            runner, current_user, runner.owner,
            name: 'ci_runner_tags_updated',
            message: 'Changed %{runner_type} CI runner tags from %{from} to %{to}',
            from: format_tag_list(previous_tag_list),
            to: format_tag_list(current_tag_list),
            additional_details: { changes: [{ change: :tag_list, from: previous_tag_list, to: current_tag_list }] }
          ).track_event
        end

        def format_tag_list(tag_list)
          "[#{tag_list.join(', ')}]"
        end
      end
    end
  end
end

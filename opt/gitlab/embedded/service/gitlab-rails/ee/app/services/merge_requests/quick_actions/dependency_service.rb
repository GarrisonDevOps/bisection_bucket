# frozen_string_literal: true

module MergeRequests
  module QuickActions
    class DependencyService < ::WorkItems::QuickActions::BaseDependencyService
      def can_block?
        @target.persisted? &&
          @target.project.licensed_feature_available?(:blocking_merge_requests) &&
          Ability.allowed?(@user, :update_merge_request, @target)
      end

      def can_admin_link?
        can_block?
      end

      def param_hint
        '<!merge_request | group/project!merge_request | merge request URL>'
      end

      def type_name
        'merge request'
      end

      def parse_params(items)
        build_extractor(items).references(:merge_request) # rubocop:disable CodeReuse/ActiveRecord -- reference extraction requires AR queries
      end

      def destroy_link(merge_request)
        block = MergeRequestBlock.for_merge_requests(@target, merge_request)
        return unless block

        ::MergeRequests::DestroyBlockService.new(
          user: @user,
          block: block
        ).execute
      end

      def create_link(merge_requests, link_type:)
        merge_requests.uniq.each do |merge_request|
          if link_type == 'blocks'
            ::MergeRequests::CreateBlockService.new(
              user: @user,
              merge_request: merge_request,
              blocking_merge_request_id: @target.id
            ).execute
          else
            ::MergeRequests::CreateBlockService.new(
              user: @user,
              merge_request: @target,
              blocking_merge_request_id: merge_request.id
            ).execute
          end
        end
      end
    end
  end
end

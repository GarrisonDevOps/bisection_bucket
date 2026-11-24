# frozen_string_literal: true

module EE
  module Search
    module Filter
      extend ::Gitlab::Utils::Override

      private

      override :filters
      def filters
        super.merge(
          **basic_filters,
          **label_filters,
          **branch_filters,
          **author_filters,
          **milestone_filters,
          **assignee_filters,
          **date_filters,
          **code_search_filters,
          **weight_filters,
          **health_status_filters
        )
      end

      def basic_filters
        {
          fields: params[:fields]
        }
      end

      def label_filters
        {
          # NOTE: label_name is used to convert names to ids and query ES by ids
          # It's deprecated, please use label_names instead
          label_name: params[:label_name],
          # NOTE: label_names searches ES by actual label names
          label_names: params[:label_names],
          not_label_names: params[:not_label_names],
          or_label_names: params[:or_label_names],
          none_label_names: params[:none_label_names],
          any_label_names: params[:any_label_names]
        }
      end

      def branch_filters
        {
          source_branch: params[:source_branch],
          not_source_branch: params[:not_source_branch],
          target_branch: params[:target_branch],
          not_target_branch: params[:not_target_branch]
        }
      end

      def author_filters
        {
          author_username: params[:author_username],
          not_author_username: params[:not_author_username]
        }
      end

      def milestone_filters
        {
          milestone_title: params[:milestone_title],
          none_milestones: params[:none_milestones],
          any_milestones: params[:any_milestones],
          not_milestone_title: params[:not_milestone_title],
          milestone_state_filters: params[:milestone_state_filters]
        }
      end

      def assignee_filters
        {
          assignee_ids: params[:assignee_ids],
          not_assignee_ids: params[:not_assignee_ids],
          or_assignee_ids: params[:or_assignee_ids],
          none_assignees: params[:none_assignees],
          any_assignees: params[:any_assignees]
        }
      end

      def date_filters
        {
          created_after: params[:created_after],
          created_before: params[:created_before],
          updated_after: params[:updated_after],
          updated_before: params[:updated_before]
        }
      end

      def code_search_filters
        {
          language: params[:language],
          num_context_lines: params[:num_context_lines]&.to_i
        }
      end

      def weight_filters
        {
          weight: params[:weight],
          not_weight: params[:not_weight],
          none_weight: params[:none_weight],
          any_weight: params[:any_weight]
        }
      end

      def health_status_filters
        {
          health_status: params[:health_status],
          not_health_status: params[:not_health_status],
          none_health_status: params[:none_health_status],
          any_health_status: params[:any_health_status]
        }
      end
    end
  end
end

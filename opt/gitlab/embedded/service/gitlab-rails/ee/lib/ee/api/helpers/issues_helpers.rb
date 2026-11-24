# frozen_string_literal: true

module EE
  module API
    module Helpers
      module IssuesHelpers
        extend ActiveSupport::Concern

        prepended do
          params :optional_issue_params_ee do
            optional :weight, type: Integer, desc: 'The weight of the issue'
            optional :epic_id, type: Integer, desc: 'ID of an epic to associate the issue with. Must be `0` or greater. Premium and Ultimate only.'
            optional :epic_iid, type: Integer, desc: 'Internal ID of an epic to associate the issue with. Must be `0` or greater. Deprecated and [scheduled for removal](https://gitlab.com/gitlab-org/gitlab/-/issues/35157) in API version 5. Premium and Ultimate only.'
            mutually_exclusive :epic_id, :epic_iid
          end

          params :negatable_issue_filter_params_ee do
            optional :weight, type: Integer, desc: 'Return issues that do not have the specified weight.'
            optional :iteration_id,
              types: [Integer, String],
              integer_or_custom_value: ::Iteration::Predefined::ALL.map { |iteration| iteration.name.downcase },
              desc: 'Return issues not assigned to the iteration with the given ID.'
            optional :iteration_title,
              type: String,
              desc: 'Return issues not assigned to the iteration with the given title.'
            mutually_exclusive :iteration_id, :iteration_title
          end

          params :issues_stats_params_ee do
            optional :weight, types: [Integer, String], integer_none_any: true, desc: 'The weight of the issue'
            optional :epic_id, types: [Integer, String], integer_none_any: true, desc: 'Return issues associated with the epic with the given ID. `None` returns issues that are not associated with an epic. `Any` returns issues that are associated with an epic. Premium and Ultimate only.'
            optional :health_status,
              type: String,
              values: ::IssuesFinder::Params::VALID_HEALTH_STATUS_PARAMS,
              coerce_with: ->(val) { val.downcase },
              desc: "The health status of the issue. Must be one of: #{::IssuesFinder::Params::VALID_HEALTH_STATUS_PARAMS.join(', ')}"
            optional :iteration_id,
              types: [Integer, String],
              integer_or_custom_value: ::Iteration::Predefined::ALL.map { |iteration| iteration.name.downcase },
              desc: 'Return issues assigned to the iteration with the given ID. `None` returns issues that do not belong to an iteration. `Any` returns issues that belong to an iteration. Premium and Ultimate only.'
            optional :iteration_title,
              type: String,
              desc: 'Return issues assigned to the iteration with the given title. Premium and Ultimate only.'
            mutually_exclusive :iteration_id, :iteration_title
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :update_params_at_least_one_of
          def update_params_at_least_one_of
            [*super, :weight, :epic_id, :epic_iid]
          end

          override :sort_options
          def sort_options
            [*super, 'weight']
          end

          override :create_issue_mcp_params
          def create_issue_mcp_params
            [*super, :epic_id]
          end

          override :create_issue_mcp_container_arguments
          def create_issue_mcp_container_arguments
            super.merge(record: { epic_id: ->(id) { ::Epic.find_by_id(id)&.group } })
          end
        end
      end
    end
  end
end

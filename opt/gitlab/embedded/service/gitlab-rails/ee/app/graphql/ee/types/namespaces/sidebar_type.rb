# frozen_string_literal: true

module EE
  module Types
    module Namespaces
      module SidebarType
        extend ActiveSupport::Concern

        prepended do
          field :open_epics_count,
            GraphQL::Types::Int,
            null: true,
            description: 'Number of open epics of the namespace.'
        end

        def open_epics_count
          return unless namespace.is_a?(Group)

          ::Groups::EpicsCountService.new(
            namespace, context[:current_user], fast_timeout: mr_and_epic_counts_fast_timeout?
          ).count
        rescue ::ActiveRecord::QueryCanceled => e # rubocop:disable Database/RescueQueryCanceled -- used with fast_read_statement_timeout to prevent this count from slowing down the rest of the request
          ::Gitlab::ErrorTracking.log_exception(e, group_id: namespace.id, query: 'group_sidebar_epics_count')
          nil
        end
      end
    end
  end
end

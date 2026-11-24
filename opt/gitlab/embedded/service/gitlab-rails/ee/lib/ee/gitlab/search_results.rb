# frozen_string_literal: true

module EE
  module Gitlab
    module SearchResults
      extend ::Gitlab::Utils::Override

      override :formatted_count
      def formatted_count(scope)
        case scope
        when 'epics'
          formatted_limited_count(limited_epics_count)
        else
          super
        end
      end

      private

      override :projects
      def projects
        super.with_compliance_framework_settings
      end

      override :merge_request_finder_params
      def merge_request_finder_params
        super.merge(merge_request_filter_params)
      end

      # Only created_at is forwarded: it is the sort key, so its range rides
      # the index scan already performed. Assignee and updated_at have no
      # index that can drive this query and stay on Advanced Search.
      def merge_request_filter_params
        {}.tap do |params|
          # Already coerced to Time by Search::Params#convert_all_date_params.
          ::Search::Params::BASIC_SEARCH_DATE_PARAMS.each do |key|
            params[key] = filters[key] if filters[key].present?
          end
        end
      end

      override :collection_for
      def collection_for(scope)
        case scope
        when 'epics'
          epics
        else
          super
        end
      end

      def limited_epics_count
        @limited_epics_count ||= limited_count(epics)
      end
    end
  end
end

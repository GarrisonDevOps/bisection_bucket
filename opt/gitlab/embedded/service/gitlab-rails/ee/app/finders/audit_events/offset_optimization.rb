# frozen_string_literal: true

module AuditEvents
  module OffsetOptimization
    PAGE_THRESHOLD_FOR_OFFSET_OPTIMIZATION = 100

    # Check if offset optimization should be used
    #
    # @param [Hash] params containing pagination parameters
    # @return [Boolean] whether offset optimization should be used
    def self.should_use_offset_optimization?(params)
      optimize_offset = params[:optimize_offset]
      optimize_offset &&
        params[:pagination] != 'keyset' &&
        params[:page].to_i >= PAGE_THRESHOLD_FOR_OFFSET_OPTIMIZATION
    end

    # Paginate using offset optimization
    #
    # @param [ActiveRecord::Relation] audit_events to paginate
    # @param [Hash] params containing page and per_page
    # @return [ActiveRecord::Relation] paginated results
    def self.paginate_with_offset_optimization(audit_events, params)
      audit_events.order(id: :desc) # rubocop:disable CodeReuse/ActiveRecord -- needed for offset optimization

      Gitlab::Pagination::Offset::PaginationWithIndexOnlyScan.new(
        scope: audit_events,
        page: params[:page],
        per_page: params[:per_page]
      ).paginate_with_kaminari
    end
  end
end

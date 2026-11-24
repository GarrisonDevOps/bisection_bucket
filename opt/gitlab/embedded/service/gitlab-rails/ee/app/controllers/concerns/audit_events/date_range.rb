# frozen_string_literal: true

module AuditEvents
  module DateRange
    extend ActiveSupport::Concern

    DATE_RANGE_LIMIT = 31

    included do
      before_action :set_date_range, :validate_date_range, only: [:index]
    end

    private

    def set_date_range
      created_before = date_range_params[:created_before]

      # rubocop:disable Rails/StrongParams -- normalizing date filter params in place for the audit event finder
      params[:created_before] = created_before.blank? ? Date.current.end_of_day : Date.parse(created_before).end_of_day
      params[:created_after] = Date.current.beginning_of_month unless date_range_params[:created_after].present?
      # rubocop:enable Rails/StrongParams
    end

    def validate_date_range
      range = date_range_params[:created_before].to_date - date_range_params[:created_after].to_date

      return unless range.days > DATE_RANGE_LIMIT.days

      message = format(_('Date range limited to %{number} days'), number: DATE_RANGE_LIMIT)
      respond_to do |format|
        format.html do
          flash[:alert] = message
          render status: :bad_request
        end
        format.any { head :bad_request }
      end
    end

    # Not memoized: set_date_range rewrites these keys in place, and
    # validate_date_range runs afterwards and must see the rewritten values.
    def date_range_params
      params.permit(:created_before, :created_after)
    end
  end
end

# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      class TermEntity < Grape::Entity
        expose(:license_id) { |term| term.license.id }
        expose(:start_date) { |term| term.period.start_date.iso8601 }
        expose(:end_date) { |term| term.end_date&.iso8601 }
        expose :current?, as: :current
      end
    end
  end
end

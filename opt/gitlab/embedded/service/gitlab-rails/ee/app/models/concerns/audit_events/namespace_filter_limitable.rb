# frozen_string_literal: true

module AuditEvents
  module NamespaceFilterLimitable
    extend ActiveSupport::Concern

    included do
      validate :namespace_filters_limit_not_exceeded, on: :create,
        if: -> { external_streaming_destination.present? }
    end

    private

    def namespace_filters_limit_not_exceeded
      max_count = ExternallyStreamable::MAXIMUM_NAMESPACE_FILTER_COUNT
      return if external_streaming_destination.namespace_filters.count < max_count

      errors.add(:namespace_filters, format(_("are limited to %{max_count} per destination"), max_count: max_count))
    end
  end
end

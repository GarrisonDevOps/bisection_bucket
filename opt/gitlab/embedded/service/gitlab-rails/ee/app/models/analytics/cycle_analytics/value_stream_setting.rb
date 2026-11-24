# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class ValueStreamSetting < ApplicationRecord
      MAX_PROJECT_IDS_FILTER = 100

      self.primary_key = :value_stream_id

      belongs_to :value_stream,
        class_name: 'Analytics::CycleAnalytics::ValueStream',
        inverse_of: :setting
      belongs_to :namespace

      validates :project_ids_filter,
        allow_blank: true,
        length: {
          maximum: MAX_PROJECT_IDS_FILTER,
          message: ->(*) { _('Maximum projects allowed in the filter is %{count}') }
        }

      validate :project_ids_filter_at_group_level

      # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- Using pluck here is safe. There is a 100 limit for project_ids_filter field.
      def project_ids_filter
        return [] if super.nil?
        return super unless value_stream&.at_group_level?

        value_stream.namespace.all_projects.id_in(super).pluck(:id)
      end
      # rubocop: enable Database/AvoidUsingPluckWithoutLimit

      private

      def project_ids_filter_at_group_level
        return unless value_stream.present?
        return unless project_ids_filter.present?
        return if value_stream.at_group_level?

        errors.add(:project_ids_filter, _('Can only be present for group level value streams'))
      end
    end
  end
end

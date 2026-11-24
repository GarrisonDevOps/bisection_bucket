# frozen_string_literal: true

module EE
  module Analytics
    module CycleAnalytics
      module ValueStream
        extend ActiveSupport::Concern

        prepended do
          has_one :setting,
            class_name: 'Analytics::CycleAnalytics::ValueStreamSetting',
            foreign_key: :value_stream_id,
            inverse_of: :value_stream

          accepts_nested_attributes_for :setting, update_only: true
        end

        def at_group_level?
          project.nil?
        end
      end
    end
  end
end

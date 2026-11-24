# frozen_string_literal: true

module EE
  module Analytics
    module CycleAnalytics
      module Stages
        module ListService
          extend ::Gitlab::Utils::Override

          def execute
            return super if filter_by_value_stream? && !value_stream.custom?
            return forbidden unless allowed? && ::Gitlab::Analytics::CycleAnalytics.licensed?(parent)

            stages = persisted_stages
            stages = filter_by_value_stream(stages)
            stages = filter_by_value_stream_ids(stages)
            stages = filter_by_stage_ids(stages)

            success(stages.for_list)
          end

          private

          def persisted_stages
            parent.cycle_analytics_stages
          end

          def filter_by_value_stream(stages)
            return stages unless filter_by_value_stream?

            stages.by_value_stream(params[:value_stream])
          end

          def filter_by_value_stream_ids(stages)
            return stages unless filter_by_value_stream_ids?

            stages.by_value_streams_ids(params[:value_stream_ids])
          end

          def filter_by_stage_ids(stages)
            return stages unless filter_by_stage_ids?

            stages.id_in(params[:stage_ids])
          end

          def filter_by_value_stream?
            params[:value_stream].present?
          end

          def filter_by_value_stream_ids?
            params[:value_stream_ids].present?
          end

          def allowed?
            ::Gitlab::Analytics::CycleAnalytics.allowed?(current_user, parent)
          end
        end
      end
    end
  end
end

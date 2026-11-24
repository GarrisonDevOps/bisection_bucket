# frozen_string_literal: true

module EE
  module Analytics
    module CycleAnalytics
      module ValueStreams
        module ListService
          extend ::Gitlab::Utils::Override

          def execute
            return forbidden unless ::Gitlab::Analytics::CycleAnalytics.allowed?(current_user, parent)
            return super unless ::Gitlab::Analytics::CycleAnalytics.licensed?(parent)

            scope = parent.value_streams
            scope = filter_by_value_stream_ids(scope)
            scope = scope.preload_associated_models.order_by_name_asc
            success(scope)
          end

          private

          def filter_by_value_stream_ids(scope)
            return scope unless params[:value_stream_ids].present?

            scope.id_in(params[:value_stream_ids])
          end
        end
      end
    end
  end
end

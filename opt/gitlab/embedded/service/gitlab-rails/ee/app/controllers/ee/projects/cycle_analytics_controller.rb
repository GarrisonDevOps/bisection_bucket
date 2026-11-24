# frozen_string_literal: true

module EE
  module Projects
    module CycleAnalyticsController
      include ::Gitlab::Utils::StrongMemoize
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :value_stream
      def value_stream
        return super unless value_stream_id_param

        project.project_namespace.value_streams.find_by_id(value_stream_id_param)
      end
      strong_memoize_attr :value_stream

      private

      def value_stream_id_param
        params.permit(:value_stream_id)[:value_stream_id]
      end
    end
  end
end

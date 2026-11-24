# frozen_string_literal: true

module EE
  module Resolvers
    module Analytics
      module CycleAnalytics
        module StagesResolver
          extend ::Gitlab::Utils::Override

          override :resolve
          def resolve(id: nil)
            return super unless ::Gitlab::Analytics::CycleAnalytics.licensed?(namespace)

            BatchLoader::GraphQL.for(object.id).batch(key: object.class.name,
              cache: false) do |value_stream_ids, loader, _|
              list_params = stage_params(id: id).merge(value_streams_ids: value_stream_ids)
              stages = list_stages(list_params)

              grouped_stages = stages.present? ? stages.group_by(&:value_stream_id) : {}

              value_stream_ids.each do |value_stream_id|
                loader.call(value_stream_id, grouped_stages[value_stream_id] || [])
              end
            end
          end

          private

          override :namespace
          def namespace
            return super unless object.at_group_level?

            object.namespace
          end
        end
      end
    end
  end
end

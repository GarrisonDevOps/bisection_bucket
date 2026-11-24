# frozen_string_literal: true

module EE
  module Resolvers
    module Analytics
      module CycleAnalytics
        module ValueStreamsResolver
          extend ::Gitlab::Utils::Override

          override :resolve
          def resolve(id: nil)
            # FOSS VSA is not supported for groups
            return if object.is_a?(Group) && !::Gitlab::Analytics::CycleAnalytics.licensed?(parent_namespace)

            super
          end

          private

          override :service_params
          def service_params(id: nil)
            params = { parent: parent_namespace, current_user: current_user, params: {} }
            params[:params][:value_stream_ids] = [::GitlabSchema.parse_gid(id).model_id] if id
            params
          end

          def parent_namespace
            object.try(:project_namespace) || object
          end
        end
      end
    end
  end
end

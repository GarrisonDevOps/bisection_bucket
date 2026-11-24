# frozen_string_literal: true

module EE
  module Analytics
    module CycleAnalytics
      module ValueStreamActions
        extend ActiveSupport::Concern

        extend ::Gitlab::Utils::Override

        def index
          return super unless ::Gitlab::Analytics::CycleAnalytics.licensed?(namespace)

          render json: ::Analytics::CycleAnalytics::ValueStreamSerializer.new.represent(value_streams)
        end

        def new
          data_attributes

          render :new
        end

        def show
          render json: ::Analytics::CycleAnalytics::ValueStreamSerializer.new.represent(value_stream)
        end

        def edit
          value_stream
          data_attributes

          render :edit
        end

        def create
          return render_404 unless can?(current_user, :create_value_stream, value_stream_access_subject)

          result = ::Analytics::CycleAnalytics::ValueStreams::CreateService.new(
            namespace: namespace,
            params: create_params,
            current_user: current_user).execute

          handle_value_stream_result result
        end

        def update
          return render_404 unless can?(current_user, :update_value_stream, value_stream_access_subject)

          result = ::Analytics::CycleAnalytics::ValueStreams::UpdateService.new(
            namespace: namespace,
            params: update_params,
            current_user: current_user,
            value_stream: value_stream).execute

          handle_value_stream_result result
        end

        def handle_value_stream_result(result)
          if result.success?
            render json: serialize_value_stream(result), status: result.http_status
          else
            render(
              json: {
                message: result.message,
                payload: { errors: serialize_value_stream_error(result) }
              },
              status: result.http_status
            )
          end
        end

        def destroy
          return render_404 unless can?(current_user, :delete_value_stream, value_stream_access_subject)

          value_stream.destroy

          render json: {}, status: :ok
        end

        private

        def project?
          namespace.is_a?(::Namespaces::ProjectNamespace)
        end

        def vsa_path
          if project?
            namespace_project_cycle_analytics_path(
              namespace_id: namespace.namespace.full_path,
              project_id: namespace.path
            )
          else
            group_analytics_cycle_analytics_path(namespace)
          end
        end

        def data_attributes
          request_params = { namespace: namespace, current_user: current_user }
          slice_attrs = [:default_stages, :namespace]

          @data_attributes = ::Gitlab::Analytics::CycleAnalytics::RequestParams.new(request_params)
            .to_data_attributes
            .slice(*slice_attrs)
            .merge(
              vsa_path: vsa_path,
              stage_events: stage_events.to_json,
              group_path: project? ? namespace.group&.full_path : namespace.full_path,
              value_stream_gid: action_name == 'edit' ? value_stream.to_global_id : nil,
              full_path: namespace.full_path,
              is_project: project?.to_s
            )
        end

        def authorize
          # Special case, project-level index action is allowed without license
          return super if action_name.eql?("index") && project?

          render_404 unless ::Gitlab::Analytics::CycleAnalytics.licensed?(namespace) &&
            ::Gitlab::Analytics::CycleAnalytics.allowed?(current_user, namespace)
        end

        def value_stream_access_subject
          ::Gitlab::Analytics::CycleAnalytics.subject_for_access_check(namespace)
        end

        def create_params
          params.require(:value_stream).permit(:name, setting: settings_params, stages: stage_create_params)
        end

        def update_params
          params.require(:value_stream).permit(:name, setting: settings_params, stages: stage_update_params)
        end

        def stage_create_params
          [
            :name,
            :start_event_identifier,
            :start_event_label_id,
            :end_event_identifier,
            :end_event_label_id,
            :custom,
            {
              start_event: [:identifier, :label_id],
              end_event: [:identifier, :label_id]
            }
          ]
        end

        def settings_params
          { project_ids_filter: [] }
        end

        def stage_update_params
          stage_create_params + [:id]
        end

        def value_streams
          @value_streams ||= namespace.value_streams.preload_associated_models.order_by_name_asc
        end

        def serialize_value_stream(result)
          ::Analytics::CycleAnalytics::ValueStreamSerializer.new.represent(result.payload[:value_stream])
        end

        def serialize_value_stream_error(result)
          ::Analytics::CycleAnalytics::ValueStreamErrorsSerializer.new(result.payload[:value_stream])
        end

        def value_stream
          @value_stream ||= namespace.value_streams.find(value_stream_id_param)
        end

        def value_stream_id_param
          params.permit(:id)[:id]
        end

        def stage_events
          selectable_events = ::Gitlab::Analytics::CycleAnalytics::StageEvents.selectable_events
          ::Analytics::CycleAnalytics::EventEntity.represent(selectable_events)
        end
      end
    end
  end
end

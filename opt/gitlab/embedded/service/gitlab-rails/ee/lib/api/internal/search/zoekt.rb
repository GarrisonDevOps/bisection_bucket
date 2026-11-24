# frozen_string_literal: true

module API
  module Internal
    module Search
      class Zoekt < ::API::Base
        before { authenticate_by_gitlab_shell_token! }

        feature_category :global_search
        urgency :low

        namespace 'internal' do
          namespace 'search' do
            namespace 'zoekt' do
              helpers do
                include Gitlab::Loggable

                params :process_metrics do
                  optional 'mmap_current', type: Integer, desc: 'Current mmap count'
                  optional 'mmap_max', type: Integer, desc: 'Maximum mmap count'
                  optional 'restarts_1m', type: Integer, desc: 'Restarts in last 1 minute'
                  optional 'restarts_5m', type: Integer, desc: 'Restarts in last 5 minutes'
                  optional 'restarts_15m', type: Integer, desc: 'Restarts in last 15 minutes'
                  optional 'rss_bytes', type: Integer, desc: 'Resident set size in bytes'
                  optional 'uptime_seconds', type: Integer, desc: 'Process uptime in seconds'
                end

                def logger
                  @logger ||= ::Search::Zoekt::Logger.build
                end

                def abort_indexing?(node)
                  return true if ::Gitlab::CurrentSettings.zoekt_indexing_paused?

                  node.watermark_exceeded_critical?
                end
              end

              route_param :uuid, type: String, desc: 'Indexer node identifier' do
                desc 'Zoekt indexer sends callback logging to Gitlab' do
                  success code: 202
                  detail 'This feature was introduced in GitLab 16.6'
                  tags %w[zoekt]
                end
                params do
                  requires :name, type: String, desc: 'Callback name'
                  requires :success, type: Boolean, desc: 'Set to true if the operation is successful'
                  optional :error, type: String, desc: 'Detailed error message'
                  requires :payload, type: JSON, desc: 'Data payload for the request'
                  optional :additional_payload, type: JSON, desc: 'Additional payload added by the Zoekt indexer'
                end
                route_setting :authorization, skip_granular_token_authorization: :gitlab_shell_token_auth
                post 'callback' do
                  node = ::Search::Zoekt::Node.find_by_uuid(params[:uuid])
                  log_data = {
                    class: 'API::Internal::Search::Zoekt', callback_name: params[:name], payload: params[:payload],
                    additional_payload: params[:additional_payload], success: params[:success], action: 'callback',
                    error_message: params[:error]
                  }
                  log_data[:meta] = node.metadata_json if node
                  log_hash = build_structured_payload(**log_data)
                  params[:success] ? logger.info(log_hash) : logger.error(log_hash)
                  break unprocessable_entity! unless node

                  ::Search::Zoekt::CallbackService.execute(node, params.except(:uuid))
                  accepted!
                end

                desc 'Fetch tasks for a zoekt indexer node' do
                  success code: 200
                  detail 'This feature was introduced in GitLab 18.0'
                  tags %w[zoekt]
                end
                params do
                  requires 'node.url', type: String, desc: 'Location where indexer can be reached'
                  requires 'disk.all', type: Integer, desc: 'Total disk space'
                  requires 'disk.used', type: Integer, desc: 'Total disk space utilized'
                  requires 'node.name', type: String, desc: 'Name of indexer node'
                  optional 'node.services', type: Array[String], desc: 'The array of services served by the node'
                  optional 'node.schema_version', type: Integer, desc: 'Schema version of the node'
                  optional 'node.knowledge_graph_schema_version', type: Integer,
                    desc: 'Knowledge graph schema version of the node (not used)'
                  optional 'disk.indexed', type: Integer, desc: 'Total indexed space'
                  optional 'process_health', type: Hash, desc: 'Process health data from indexer and webserver' do
                    optional 'indexer', type: Hash, desc: 'Indexer process health metrics' do
                      use :process_metrics
                    end
                    optional 'webserver', type: Hash, desc: 'Webserver process health metrics (relayed via indexer)' do
                      use :process_metrics
                      optional 'shards_loaded', type: Integer, desc: 'Number of shards loaded'
                    end
                  end
                end
                route_setting :authorization, skip_granular_token_authorization: :gitlab_shell_token_auth
                post 'heartbeat' do
                  node = ::Search::Zoekt::Node.find_or_initialize_by_task_request(params)
                  new_node = node.new_record?

                  if node.save_debounce
                    status :ok
                    { id: node.id, truncate: new_node }.tap do |resp|
                      resp[:tasks] = ::Search::Zoekt::TaskPresenterService.execute(node)
                      resp[:pull_frequency] = node.task_pull_frequency
                      resp[:stop_indexing] = abort_indexing?(node)
                    end
                  else
                    unprocessable_entity!
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

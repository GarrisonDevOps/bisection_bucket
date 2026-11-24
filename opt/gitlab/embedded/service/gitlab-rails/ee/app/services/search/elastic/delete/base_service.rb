# frozen_string_literal: true

module Search
  module Elastic
    module Delete
      class BaseService
        include Gitlab::Loggable

        QUERY_TIMEOUT = '10m'

        def self.execute(options)
          new(options).execute
        end

        def initialize(options = {})
          @options = options.with_indifferent_access
        end

        def execute
          remove_documents
        end

        private

        attr_reader :options

        # Builds a query to delete documents for a project from the Elasticsearch index.
        # Supports two modes:
        # - Project transfer (project_id + traversal_id): deletes docs from project ignoring the given traversal_id.
        #   i.e deletes docs with old traversal_id for the given project.
        # - Project deletion (project_id only): deletes all docs for the project
        def build_query
          project_id = options[:project_id]
          traversal_id = options[:traversal_id]
          if project_id.nil?
            Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
              ArgumentError.new('project_id is required')
            )
            return
          end

          filter_list = [{ term: { project_id: project_id } }]

          unless traversal_id.nil?
            filter_list << { bool: { must_not: { prefix: { traversal_ids: { value: traversal_id } } } } }
          end

          {
            query: {
              bool: {
                filter: filter_list
              }
            }
          }
        end

        def index_name
          raise NotImplementedError
        end

        def remove_documents
          return if build_query.blank?

          response = client.delete_by_query({
            index: index_name,
            conflicts: 'proceed',
            timeout: QUERY_TIMEOUT,
            body: build_query
          })

          log_response(response)
        end

        def log_response(response)
          if response['failure'].present?
            log_error(response)
          else
            log_success(response)
          end
        end

        def log_error(response)
          payload = build_structured_payload(
            **options,
            failure: response['failure'],
            message: 'Failed to delete documents',
            index: index_name
          )
          logger.error(payload)
        end

        def log_success(response)
          payload = build_structured_payload(
            **options,
            deleted: response['deleted'],
            message: 'Successfully deleted documents',
            index: index_name
          )
          logger.info(payload)
        end

        def client
          @client ||= ::Gitlab::Search::Client.new
        end

        def logger
          @logger ||= ::Gitlab::Elasticsearch::Logger.build
        end
      end
    end
  end
end

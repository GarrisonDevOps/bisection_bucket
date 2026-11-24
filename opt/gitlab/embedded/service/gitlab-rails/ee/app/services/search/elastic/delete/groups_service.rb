# frozen_string_literal: true

module Search
  module Elastic
    module Delete
      class GroupsService < BaseService
        private

        def index_name
          ::Search::Elastic::Types::Group.index_name
        end

        def build_query
          group_ids = options[:group_ids]
          ancestor_id = options[:ancestor_id]

          if group_ids.blank? || ancestor_id.nil?
            Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
              ArgumentError.new('group_ids and ancestor_id are required')
            )
            return
          end

          {
            query: {
              bool: {
                filter: { terms: { id: Array.wrap(group_ids) } }
              }
            }
          }
        end

        def remove_documents
          return if build_query.blank?
          return unless defined?(::Search::Elastic::Types::Group)

          ancestor_id = options[:ancestor_id]

          response = client.delete_by_query({
            index: index_name,
            routing: "group_#{ancestor_id}",
            conflicts: 'proceed',
            timeout: QUERY_TIMEOUT,
            body: build_query
          })

          log_response(response)
        rescue Elasticsearch::Transport::Transport::Errors::NotFound
          # Index doesn't exist yet, nothing to delete
          nil
        end
      end
    end
  end
end

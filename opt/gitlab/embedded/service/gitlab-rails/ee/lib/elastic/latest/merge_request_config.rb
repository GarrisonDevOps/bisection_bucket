# frozen_string_literal: true

module Elastic
  module Latest
    module MergeRequestConfig
      # To obtain settings and mappings methods
      extend Elasticsearch::Model::Indexing::ClassMethods
      extend Elasticsearch::Model::Naming::ClassMethods

      def self.index_name
        [Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, 'merge_requests'].join('-')
      end

      settings Elastic::Latest::Config.settings.to_hash.deep_merge(
        index: {
          number_of_shards: Elastic::AsJSON.new { Elastic::IndexSetting[index_name].number_of_shards },
          number_of_replicas: Elastic::AsJSON.new { Elastic::IndexSetting[index_name].number_of_replicas }
        }
      )

      mappings dynamic: 'strict' do
        indexes :type, type: :keyword
        indexes :id, type: :long
        indexes :iid, type: :integer

        indexes :title, type: :text, index_options: 'positions', analyzer: :title_analyzer
        indexes :description, type: :text, index_options: 'positions', analyzer: :code_analyzer
        indexes :state, type: :keyword
        indexes :project_id, type: :long
        indexes :author_id, type: :long
        indexes :traversal_ids, type: :keyword
        indexes :organization_id, type: :long
        indexes :organization_traversal_ids, type: :keyword

        indexes :target_branch, type: :keyword
        indexes :source_branch, type: :keyword
        indexes :merge_status, type: :keyword
        indexes :source_project_id, type: :long
        indexes :target_project_id, type: :long

        indexes :created_at, type: :date
        indexes :updated_at, type: :date

        indexes :hidden, type: :boolean
        indexes :archived, type: :boolean
        indexes :visibility_level, type: :integer
        indexes :merge_requests_access_level, type: :integer
        indexes :upvotes, type: :integer
        indexes :label_ids, type: :keyword
        indexes :assignee_ids, type: :keyword

        indexes :hashed_root_namespace_id, type: :integer
        indexes :schema_version, type: :short
      end
    end
  end
end

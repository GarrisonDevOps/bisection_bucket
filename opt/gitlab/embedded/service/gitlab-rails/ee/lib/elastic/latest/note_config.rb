# frozen_string_literal: true

module Elastic
  module Latest
    module NoteConfig
      # To obtain settings and mappings methods
      extend Elasticsearch::Model::Indexing::ClassMethods
      extend Elasticsearch::Model::Naming::ClassMethods

      def self.index_name
        [Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, 'notes'].join('-')
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

        indexes :note, type: :text, index_options: 'positions', analyzer: :code_analyzer
        indexes :project_id, type: :long
        indexes :traversal_ids, type: :keyword
        indexes :organization_id, type: :long
        indexes :organization_traversal_ids, type: :keyword

        indexes :noteable_type, type: :keyword
        indexes :noteable_id, type: :long

        indexes :created_at, type: :date
        indexes :updated_at, type: :date

        indexes :confidential, type: :boolean
        indexes :internal, type: :boolean
        indexes :hidden, type: :boolean

        indexes :visibility_level, type: :integer
        indexes :issues_access_level, type: :integer
        indexes :repository_access_level, type: :integer
        indexes :merge_requests_access_level, type: :integer
        indexes :snippets_access_level, type: :integer

        indexes :issue do
          indexes :assignee_id, type: :long
          indexes :author_id, type: :long
          indexes :confidential, type: :boolean
        end

        indexes :hashed_root_namespace_id, type: :integer
        indexes :schema_version, type: :short

        indexes :archived, type: :boolean
      end
    end
  end
end

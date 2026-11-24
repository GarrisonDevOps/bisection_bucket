# frozen_string_literal: true

module Elastic
  module Latest
    module WikiConfig
      # To obtain settings and mappings methods
      extend Elasticsearch::Model::Indexing::ClassMethods
      extend Elasticsearch::Model::Naming::ClassMethods

      def self.index_name
        [Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, 'wikis'].join('-')
      end

      settings Elastic::Latest::Config.settings.to_hash.deep_merge(
        index: Elastic::Latest::Config.separate_index_specific_settings(index_name)
      )

      mappings dynamic: 'strict' do
        indexes :type, type: :keyword

        indexes :project_id, type: :long
        indexes :group_id, type: :long
        indexes :rid, type: :keyword
        indexes :oid, type: :keyword, index_options: 'docs', normalizer: :sha_normalizer
        indexes :traversal_ids, type: :keyword
        indexes :organization_id, type: :long
        indexes :organization_traversal_ids, type: :keyword

        indexes :visibility_level, type: :integer
        indexes :wiki_access_level, type: :integer

        indexes :commit_sha, type: :keyword, index_options: 'docs', normalizer: :sha_normalizer

        indexes :path, type: :text, analyzer: :path_analyzer
        indexes :file_name,
          type: :text, analyzer: :code_analyzer,
          fields: { reverse: { type: :text, analyzer: :whitespace_reverse } }

        indexes :content,
          type: :text, index_options: 'positions', analyzer: :text_analyzer
        indexes :language, type: :keyword

        indexes :schema_version, type: :short

        indexes :archived, type: :boolean
      end
    end
  end
end

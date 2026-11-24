# frozen_string_literal: true

module Elastic
  module Latest
    module ProjectConfig
      # To obtain settings and mappings methods
      extend Elasticsearch::Model::Indexing::ClassMethods
      extend Elasticsearch::Model::Naming::ClassMethods

      def self.index_name
        [Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, 'projects'].join('-')
      end

      settings Elastic::Latest::Config.settings.to_hash.deep_merge(
        index: Elastic::Latest::Config.separate_index_specific_settings(index_name)
      )

      mappings dynamic: 'strict' do
        indexes :id, type: :long
        indexes :created_at, type: :date
        indexes :updated_at, type: :date

        indexes :type, type: :keyword
        indexes :name, type: :text, index_options: 'positions'
        indexes :path, type: :text, index_options: 'positions'

        indexes :name_with_namespace, type: :text, index_options: 'positions', analyzer: :my_ngram_analyzer
        indexes :description, type: :text, index_options: 'positions'
        indexes :path_with_namespace, type: :text, index_options: 'positions'
        indexes :namespace_id, type: :long

        indexes :archived, type: :boolean
        indexes :traversal_ids, type: :keyword
        indexes :organization_id, type: :long
        indexes :organization_traversal_ids, type: :keyword
        indexes :visibility_level, type: :integer

        indexes :last_activity_at, type: :date
        indexes :schema_version, type: :short

        indexes :ci_catalog, type: :boolean
        indexes :readme_content, type: :text

        indexes :mirror, type: :boolean
        indexes :forked, type: :boolean
        indexes :owner_id, type: :long
        indexes :repository_languages, type: :keyword

        indexes :star_count, type: :integer
        indexes :last_repository_updated_date, type: :date
      end
    end
  end
end

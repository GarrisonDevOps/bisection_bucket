# frozen_string_literal: true

class CreateCode < ActiveContext::Migration[1.0]
  milestone '18.6'

  # 24 partitions = 48 shards * 50 GB = 2400 GB
  # The total potential capacity for GitLab.com would be 2.4 TB
  GITLAB_COM_NUMBER_OF_PARTITIONS = 24
  MINIMUM_PARTITIONS = 2

  REPOSITORY_MULTIPLIER = 0.5
  PARTITION_CAPACITY_GB = 100 # 1 partition = 2 shards of 50 GB
  GROWTH_MULTIPLIER = 2

  def migrate!
    create_collection :code, number_of_partitions: number_of_partitions,
      options: { include_ref_fields: false } do |c|
      c.keyword :id
      c.bigint :project_id
      c.keyword :path
      c.smallint :type
      c.text :content
      c.text :name
      c.keyword :source
      c.keyword :language
      c.boolean :reindexing
      c.vector :embeddings_v1, dimensions: 768
    end
  end

  def number_of_partitions
    return GITLAB_COM_NUMBER_OF_PARTITIONS if Gitlab::Saas.feature_available?(:duo_chat_on_saas)

    total_repo_size = Namespace::RootStorageStatistics.sum(:repository_size).to_i
    estimated_index_size = total_repo_size * REPOSITORY_MULTIPLIER
    estimated_growth_size = estimated_index_size * GROWTH_MULTIPLIER
    calculated_partitions = (estimated_growth_size / 1.gigabyte / PARTITION_CAPACITY_GB).ceil
    [calculated_partitions, MINIMUM_PARTITIONS].max
  end
end

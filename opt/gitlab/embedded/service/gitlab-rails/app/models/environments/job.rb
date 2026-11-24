# frozen_string_literal: true

module Environments
  class Job < ApplicationRecord
    include Ci::Partitionable::AssociationFinder

    self.table_name = 'job_environments'

    belongs_to :environment
    belongs_to :project
    belongs_to :pipeline, class_name: 'Ci::Pipeline', foreign_key: :ci_pipeline_id, inverse_of: :job_environments
    belongs_to :job, class_name: 'Ci::Processable', foreign_key: :ci_job_id, inverse_of: :job_environment
    belongs_to :deployment
    partitionable_belongs_to_loader :pipeline

    validates :environment_id, :project_id, :ci_pipeline_id, :ci_job_id, presence: true
    validates :ci_job_id, uniqueness: { scope: :environment_id }
    validates :options, json_schema: { filename: 'environments_job_options', size_limit: 256.bytes }
    validates :expanded_environment_name,
      presence: true,
      length: { maximum: 255 },
      format: { with: Gitlab::Regex.environment_name_regex,
                message: Gitlab::Regex.environment_name_regex_message }

    attribute :options, ::Gitlab::Database::Type::SymbolizedJsonb.new

    # No index orders an environment's job links by ID, so each batch takes the next rows by `LIMIT`
    def self.delete_batch_for_environment(environment, batch_size)
      where(environment: environment).limit(batch_size).delete_all
    end

    def self.exists_for?(environment)
      where(environment: environment).exists?
    end
  end
end

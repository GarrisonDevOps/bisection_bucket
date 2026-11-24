# frozen_string_literal: true

module EE
  module Types
    module Ci
      module StageType
        extend ActiveSupport::Concern

        prepended do
          private

          def preload_deployment_associations(jobs)
            processable_jobs = jobs.select { |job| job.is_a?(::Ci::Processable) }
            return if processable_jobs.empty?

            ActiveRecord::Associations::Preloader.new(
              records: processable_jobs,
              associations: [:job_environment, { deployment: :environment }]
            ).call
          end
        end
      end
    end
  end
end

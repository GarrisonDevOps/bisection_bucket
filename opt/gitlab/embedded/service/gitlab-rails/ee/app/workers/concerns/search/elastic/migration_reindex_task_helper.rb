# frozen_string_literal: true

module Search
  module Elastic
    module MigrationReindexTaskHelper
      def migrate
        return if targets.empty?

        Search::Elastic::ReindexingTask.create!(
          targets: targets,
          options: { skip_pending_migrations_check: true }
        )
      end

      def completed?
        true
      end
    end
  end
end

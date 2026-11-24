# frozen_string_literal: true

class PopulateSearchIndexValidationDocuments < Elastic::Migration
  def migrate
    result = ::Search::ClusterHealthCheck::IndexValidationService.execute
    set_migration_state(service_result: result)
  end

  def completed?
    true
  end
end

PopulateSearchIndexValidationDocuments.prepend ::Search::Elastic::MigrationObsolete

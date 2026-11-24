# frozen_string_literal: true

class AddRoutingToIssues < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Issue

  private

  def new_mappings
    { routing: { type: 'keyword' } }
  end
end

AddRoutingToIssues.prepend ::Search::Elastic::MigrationObsolete

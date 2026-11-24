# frozen_string_literal: true

class ReviseVulnerabilitiesMappingsAndFieldTypes < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[Vulnerability]
  end
end

ReviseVulnerabilitiesMappingsAndFieldTypes.prepend ::Search::Elastic::MigrationObsolete

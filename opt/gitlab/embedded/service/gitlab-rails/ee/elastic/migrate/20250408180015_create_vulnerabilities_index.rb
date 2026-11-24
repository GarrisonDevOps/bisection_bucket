# frozen_string_literal: true

class CreateVulnerabilitiesIndex < Elastic::Migration
  include ::Search::Elastic::MigrationCreateIndexHelper

  retry_on_failure

  def document_type
    :vulnerabilities
  end

  # Name of the type class.
  def target_class
    ::Vulnerability
  end
end

CreateVulnerabilitiesIndex.prepend ::Search::Elastic::MigrationObsolete

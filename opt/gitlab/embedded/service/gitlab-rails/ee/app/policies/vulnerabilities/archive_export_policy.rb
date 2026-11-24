# frozen_string_literal: true

module Vulnerabilities
  class ArchiveExportPolicy < BasePolicy
    delegate { @subject.project }

    condition(:is_author) { @user && @subject.author == @user }
    condition(:exportable) { can?(:create_vulnerability_archive_export, @subject.project) }

    rule { exportable & is_author }.policy do
      enable :read_vulnerability_archive_export
    end
  end
end

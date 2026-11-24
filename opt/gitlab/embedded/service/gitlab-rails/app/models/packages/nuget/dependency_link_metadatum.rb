# frozen_string_literal: true

class Packages::Nuget::DependencyLinkMetadatum < ApplicationRecord
  self.primary_key = :dependency_link_id

  belongs_to :dependency_link, inverse_of: :nuget_metadatum

  validates :dependency_link, :target_framework, presence: true

  validate :ensure_nuget_package_type

  private

  def ensure_nuget_package_type
    return if dependency_link&.package&.nuget?

    errors.add(:base, format(_('Package type must be %{package_type}'), package_type: 'NuGet'))
  end
end
